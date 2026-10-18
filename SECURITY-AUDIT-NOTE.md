# Audit de sécurité — Fork Keycloak `vespere-labs/keycloak`

**Date :** 16 octobre 2026 · **Auditeur :** Agent Vibe Code · **Classification :** Interne

---

## 1. Contexte et périmètre

- **Dépôt audité :** fork `vespere-labs/keycloak`, clone à l'identique d'`keycloak/keycloak@main` (commit `a33d8918`, du 16/10/2026). Aucune divergence locale : le risque du fork est donc directement hérité de l'upstream.
- **Version code :** `999.0.0-SNAPSHOT` (branche de dev, post-26.8.1).
- **Stack :** Quarkus 3.40.1 · RESTEasy 6.2.19.Final · Infinispan 16.0.15 · Node 24 / pnpm 11.
- **Méthode :** revue statique ciblée (grep patterns à risque : secrets codés en dur, crypto faible, SSRF, XSS, désérialisation), revue des workflows CI (supply chain), corrélation avec le registre officiel des advisories GitHub de `keycloak/keycloak` (29 CVE listées) et les guides de migration officiels (correctifs 26.7.x → 26.8.1).

## 2. Score global de cybersécurité

| Indicateur | Valeur | Note |
|---|---|---|
| **Score global pondéré** | **7,5 / 10** | Code upstream à jour et activement maintenu |
| Vulnérabilités connues actives | 0 corrigée manquante (fork post-26.8.1) | Les 29 CVE du registre sont patchées dans cette snapshot |
| Secrets en dur | 0 constaté (clés de test uniquement) | — |
| Supply chain CI | Bonne (actions épinglées par SHA) | Pin SHA-1 système fiable |
| Risques résiduels "inconnus" | 6 constatés | Faiblesse intrinsèque du produit, pas du fork |

**Verdict : le code est sain mais le snapshot "dev" n'est pas une base de production.** Le risque principal n'est pas le code présent, mais l'usage d'une branche SNAPSHOT non release pour déployer.

## 3. Tableau de synthèse des failles

### 3.1 Failles connues (CVE historiques — corrigées dans ce snapshot, à surveiller en régression)

| CVE | Composant | Type | Gravité | Corrigée dans | Statut fork |
|---|---|---|---|---|---|
| CVE-2026-90997 | keycloak-services | Bypass de protection anti-replay via sémantiques BDD | High | 26.8.1 | ✅ corrigée |
| CVE-2026-16102 | keycloak-services | Forgeries de rôles via mappers user property (DCR) | High | 26.8.x | ✅ corrigée |
| CVE-2026-16071 | keycloak-services | Recherche LDAP entry-dn hors périmètre | Medium | 26.8.x | ✅ corrigée |
| CVE-2026-16443 | keycloak-services | Import metadata SAML désactive validation signature | High | 26.8.x | ✅ corrigée |
| CVE-2026-16442 | keycloak-services | IdP-initiated SAML bypass | High | 26.8.x | ✅ corrigée |
| CVE-2026-16100 | keycloak-services | Cardinalité métriques non bornée (DoS) | Medium | 26.8.x | ✅ corrigée |
| CVE-2026-15572 | keycloak-services | Bypass policy DCR par swap de type mapper | High | 26.8.x | ✅ corrigée |
| CVE-2026-15573 | keycloak-services | Bypass authz par URI non normalisé (PathMatcher) | High | 26.8.x | ✅ corrigée |
| CVE-2026-11800 | OIDC | Auth bypass par confusion d'algorithme JWT | High | 26.7.x | ✅ corrigée |
| CVE-2026-9800 | OIDC | Bypass authz par comparaison URI incorrecte | High | 26.6.4 | ✅ corrigée |
| CVE-2026-9799 | Authorization | Accès non autorisé via bypass permission ticket UMA | Medium | 26.6.4 | ✅ corrigée |
| CVE-2026-9795 | Authorization | Élévation de privilèges par mauvaise application des scopes | High | 26.6.4 | ✅ corrigée |
| CVE-2026-9705 | Client registration | Ré-activation / takeover de clients désactivés | Medium | 26.6.4 | ✅ corrigée |
| CVE-2026-9086 | URI validation | XSS par bypass casse-insensible | High | 26.6.4 | ✅ corrigée |
| CVE-2026-9083 | Services | Information disclosure par probing de chemins fichiers | Medium | 26.6.4 | ✅ corrigée |
| CVE-2026-9099 | Admin RBAC | Élévation group-admin → realm-admin | High | 26.6.4 | ✅ corrigée |
| CVE-2026-2092 | SAML | Accès non autorisé par validation d'assertions chiffrées | High | 26.5.x | ✅ corrigée |
| CVE-2026-17048 | Admin REST | Fuite de secrets client résolus par vault | High | 26.7.2 | ✅ corrigée |
| CVE-2026-15571 | OIDC | Hash de account-linking prédictible → takeover | High | 26.7.2 | ✅ corrigée |
| CVE-2026-18963 | reset-credentials | **Prise de contrôle de compte non authentifiée** | **Critical** | 26.7.2 | ✅ corrigée |
| CVE-2026-96446 | OIDC/PAR | Bypass single-use PAR via `prompt=none` | High | 26.7.3 | ✅ corrigée |
| CVE-2026-9793 | OIDC | Request object JWE bypass de `requestObjectSignatureAlg` | High | 26.7.x | ✅ corrigée |
| CVE-2026-18569 | OIDC logout | Forcing de logout par token forgé (`alg=none`) | High | 26.8.1 | ✅ corrigée |
| CVE-2026-15943 | Identity providers | Exfiltration du client secret par redirection de destination | High | 26.8.1 | ✅ corrigée |
| CVE-2026-107121 | SMTP | Downgrade STARTTLS opportuniste | Medium | 26.8.1 | ✅ corrigée |
| CVE-2026-45292 | OpenTelemetry | Allocation mémoire non bornée (baggage W3C) | Medium | 26.7.2 | ✅ corrigée |
| CVE-2026-1609 | quarkus-server | Accès non autorisé via JWT grant avec utilisateurs désactivés | High | 26.7.x | ✅ corrigée |
| CVE-2025-13467 | LDAP federation | Désérialisation de données non fiables | Medium | 26.2.x | ✅ corrigée |
| CVE-2025-11419 | TLS | DoS par renegotiation initiée par le client | High | 26.x | ✅ corrigée |

### 3.2 Failles résiduelles / potentielles ("inconnues" — constats de l'audit statique)

| # | Localisation | Constat | Gravité | CWE |
|---|---|---|---|---|
| F1 | `saml-core/.../BaseSAML2BindingBuilder.java:69` | Algorithme de signature SAML par défaut = **RSA_SHA1** (SHA-1 déprécié). Surchargeable mais valeur par défaut faible | Medium | CWE-327 |
| F2 | `server-spi/.../OTPPolicy.java:75` | Politique OTP par défaut = **HmacSHA1**, 6 chiffres, période 30s — entropie et robustesse minimales ; SHA-1 reste toléré pour TOTP mais faible | Low/Medium | CWE-327 |
| F3 | `services/.../vault/FilesPlainTextVaultProviderFactory.java` | Vault "files-plaintext" : secrets stockés **en clair sur disque**, sans chiffrement au repos, protection par permissions OS uniquement | High si utilisé en prod | CWE-312 |
| F4 | `util/.../KerberosKeytabCreator.java:45-49` | Enctypes Kerberos incluant encore **DES_CBC_MD5** et DES3-CBC-SHA1-KD (crypto legacy) dans l'outil de génération de keytab (usage test/outils) | Low | CWE-327 |
| F5 | Ensemble du dépôt | Snapshot `999.0.0-SNAPSHOT` : aucune garantie de stabilité ni d'anneau de tests de release ; risque de régression silencieuse d'un correctif de sécurité | Medium (process) | — |
| F6 | Workflows CI (`.github/actions/azure-create-database`) | Secrets transmis en inputs d'action composite — risque de fuite dans les logs si `echo`/`set -x` activé (actuellement OK, pattern fragile) | Low | CWE-532 |

**Points positifs constatés :** aucune clé privée/secret en dur en dehors des fixtures de test ; cookies avec SameSite/HttpOnly/Secure gérés dans `DefaultCookieProvider` ; validation des redirects URI systématique (`RedirectUtils.verifyRedirectUri`) ; actions GitHub épinglées par SHA de commit ; workflow `scan-dependencies` quotidien ; `SECURITY-INSIGHTS.yml` présent.

## 4. Vulnérabilités analysées — liste consolidée

**CVE analysées (29) :** CVE-2026-90997, CVE-2026-16102, CVE-2026-16071, CVE-2026-16443, CVE-2026-16442, CVE-2026-16100, CVE-2026-15572, CVE-2026-15573, CVE-2026-11800, CVE-2026-9800, CVE-2026-9799, CVE-2026-9795, CVE-2026-9705, CVE-2026-9086, CVE-2026-9083, CVE-2026-9099, CVE-2026-2092, CVE-2026-17048, CVE-2026-15571, CVE-2026-18963, CVE-2026-96446, CVE-2026-9793, CVE-2026-18569, CVE-2026-15943, CVE-2026-107121, CVE-2026-45292, CVE-2026-1609, CVE-2025-13467, CVE-2025-11419.

**Constats statiques (6) :** F1 SHA-1 SAML défaut, F2 OTP SHA-1 défaut, F3 vault plaintext, F4 enctypes Kerberos legacy, F5 risque snapshot non-release, F6 pattern secrets CI.

## 5. Remédiations critiques à appliquer (priorisées)

| Priorité | Action | Justification |
|---|---|---|
| **P0** | Ne pas déployer ce snapshot SNAPSHOT en production : baser tout déploiement sur la **dernière release stable officielle** (≥ 26.8.1) | Les releases passent l'anneau de tests complet ; un snapshot peut régresser un correctif de sécurité |
| **P0** | Si un vault fichiers est utilisé : **migrer vers le vault keystore chiffré** (`--vault-type=keystore`) ou un provider vault (HashiCorp/AWS/GCP) | F3 : secrets en clair sur disque |
| **P1** | Pour tout client SAML créé via ce code : **forcer `RSA_SHA256` ou plus** comme algorithme de signature et interdire RSA_SHA1/DSA_SHA1 par policy client | F1 |
| **P1** | Renforcer la politique OTP realm par défaut : **HmacSHA256/512**, 30s, et exiger OTP sur les comptes admin | F2 |
| **P1** | Configuration de production stricte : `start --optimized` (jamais `start-dev`), TLS obligatoire, `http-enabled=false`, hostname v2 explicite, `proxy-headers=forwarded` uniquement derrière proxy de confiance | Durcissement de surface (prévention des classes CVE bind/debug : cf. CVE-2025-11538/10939) |
| **P2** | Sur le fork : mettre en place une **synchronisation automatique hebdomadaire avec upstream** + veille sur `gh api repos/keycloak/keycloak/security-advisories` pour absorber les futurs correctifs sous 7 jours | Le fork divergeant est le principal risque futur |
| **P2** | Enctypes Kerberos : restreindre à AES256/128 uniquement dans les outils internes | F4 |
| **P2** | CI : remplacer les inputs secrets des actions composite par `secrets` + environment GitHub, et activer `--quiet` sur les étapes manipulant des credentials | F6 |

## 6. Conclusion

Le fork est un miroir fidèle et **à jour** de l'upstream au 16/10/2026 : aucune des 29 CVE connues du registre officiel n'y est exploitable. Le score de 7,5/10 reflète un produit sain mais au périmètre d'attaque très large (OIDC, SAML, DCR, UMA, LDAP, admin REST, SMTP, brokering) qui produit historiquement ~1 CVE high par trimestre — la remédiation la plus importante est donc **opérationnelle** (rester synchronisé, durcir la configuration, ne pas déployer de SNAPSHOT) plutôt que corrective sur le code lui-même.

---

## 7. Analyse approfondie « ligne par ligne » (revue ciblée des zones critiques)

Périmètre réel couvert : ~766 000 lignes Java main + modules JS. Revue exhaustive des fichiers de sécurité critiques (authentification, JOSE/JWS, PKCE, XML/SAML, LDAP, templates, cookies, brute force, conteneur).

### 7.1 Constats nouveaux (candidats CVE / faiblesses)

| # | Localisation exacte | Constat | Gravité estimée | CWE |
|---|---|---|---|---|
| N1 | `services/.../oidc/utils/PkceUtils.java:58` | **PKCE `plain` accepté** : `verifier.equals(codeChallenge)` — la méthode "plain" de PKCE est admise (RFC 6749 la tolère) et annoncée dans `.well-known` (`OIDCWellKnownProvider.java:93`). Un MITM TLS peut réutiliser le challenge. S256 est recommandé mais non imposé par défaut | **Medium** | CWE-327 |
| N2 | `services/.../utils/PkceUtils.java:58,61,131` | Comparaison du code challenge **non en temps constant** (`String.equals`) — canal latéral timing théorique. NB : TOTP et recovery codes utilisent correctement `MessageDigest.isEqual` (`HmacOTP.java:87`, `RecoveryAuthnCodesUtils.java:46`) et les secrets client aussi (`model/jpa/ClientAdapter.java:234`) | Low (théorique) | CWE-208 |
| N3 | `services/.../broker/oidc/OIDCIdentityProvider.java:570` | `error_description` renvoyé par un IdP externe **interpolé directement dans un message d'exception** (`IdentityBrokerException`) — peut se propager dans les logs, la réponse d'erreur brokering ou l'UI sans encodage préalable ; similaire dans sa classe à CVE-2025-10044 (corrigée pour les pages d'erreur principales) | Low/Medium | CWE-79/532 |
| N4 | `services/.../executors/DefaultExecutorsProviderFactory.java:202` | `new Random().nextInt(2048)` — `java.util.Random` non cryptographique. Ici utilisé uniquement pour nommer les threads (non exploitable) mais pattern à procrire | Info | CWE-338 |
| N5 | `services/.../connections/httpclient/DefaultHttpClientFactory.java:300` | `Math.random()` pour le jitter de retry — idem, non sensible | Info | CWE-338 |
| N6 | `crypto/default/.../Argon2Parameters.java:13` | Argon2 par défaut : **5 itérations, 7 168 KiB, parallélisme 1** — conforme OWASP minimum mais paramètres bas si Argon2 activé en prod | Low (durcissement) | CWE-916 |
| N7 | `saml-core/.../BaseSAML2BindingBuilder.java:69` (déjà F1) + `saml-core/.../SignatureAlgorithm.java:29-51` | RSA_SHA1/DSA_SHA1 **toujours présents et mappés** — Même si dépréciés, ils restent sélectionnables côté clients SAML | Medium | CWE-327 |

### 7.2 Zones vérifiées et jugées saines (aucune faille trouvée)

| Zone | Fichiers | Verdict |
|---|---|---|
| **XXE / entités XML** | `saml-core/.../StaxParserUtil.java:938-942` | ✅ `SUPPORT_DTD=false`, `IS_SUPPORTING_EXTERNAL_ENTITIES=false`, DTD désactivées — XXE correctement neutralisé |
| **Injection LDAP** | `federation/ldap/.../EqualCondition.java`, `NamedParameterCondition.java:66` | ✅ `escapeValue()` → `OctetStringEncoder(EscapeStrategy.DEFAULT)` : échappement systématique des valeurs |
| **Injection SQL** | `model/jpa/**` | ✅ Zéro requête concaténée ; 100 % JPA paramétré |
| **SSTI (templates)** | `services/.../theme/freemarker/DefaultFreeMarkerProvider.java:64` | ✅ `HTMLOutputFormat` imposé (auto-échappement HTML) |
| **Cookies** | `services/.../cookie/DefaultCookieProvider.java:54-74` | ✅ SameSite/Secure/HttpOnly gérés, dégradation `NONE→LAX` en HTTP |
| **Anti-brute-force** | `DefaultBruteForceProtector.java`, `AuthenticationManager.java:1773` | ✅ Mécanisme complet (compteur, lockout, événements) |
| **Page welcome / CSRF** | `WelcomeResource.java:295-316` | ✅ `isLocal` exige absence de `X-Forwarded-For`/`Forwarded` + adresses locales réelles ; CSRF token sur les actions |
| **Scripting (RCE)** | `DefaultScriptingProvider.java` + `Profile.java:88` | ✅ Feature `SCRIPTS` = `Type.PREVIEW` (désactivée par défaut en prod) |
| **Génération de secrets** | `common/.../SecretGenerator.java:34`, `KeyUtils.java:89`, `JWEUtils.java:32`, `SdJwtUtils.java:43`, `MdocCredential.java:47` | ✅ `SecureRandom` partout où c'est sensible |
| **Hash de mots de passe** | `Pbkdf2Sha256PasswordHashProviderFactory.java:19` (600 000 itér.), `Pbkdf2Sha512...:42` (1 300 000) | ✅ Aligné OWASP Password Storage Cheat Sheet |
| **JWT identity cookie** | `AuthenticationManager.java:1550-1590` | ✅ `withDefaultChecks()`, vérification `kid` + provider d'algorithme (`signatureProvider == null` → rejet), confusion d'algorithme bloquée |
| **SAML signature wrapping** | `saml-core/.../XMLSignatureUtil.java:186,206,575-594` | ✅ Validation par élément `Reference` (et non par position — le bug historique est corrigé) |
| **Comparaisons de secrets client** | `model/jpa/ClientAdapter.java:234`, `model/infinispan/ClientAdapter.java:199` | ✅ `MessageDigest.isEqual` (temps constant) |
| **Conteneur** | `quarkus/container/Dockerfile:34` | ✅ `USER 1000`, non-root |
| **Supply chain CI** | `.github/workflows/*` | ✅ Actions épinglées par SHA de commit |
| **Recherche SSRF** | `ClientHostUtils.java:135`, `TrustedHostClientRegistrationPolicy.java:251`, `StackoverflowIdentityProvider.java:114` | ✅ URLs validées/peu exposées ; aucun `new URL()` non validé alimenté par l'utilisateur trouvé dans `services/src/main` |

### 7.3 Conclusion de l'analyse ligne par ligne

Aucune **nouvelle CVE exploitable** n'a été identifiée par rapport au registre officiel (29 CVE déjà patchées dans ce snapshot). Les constats N1 (PKCE `plain`) et N7 (RSA_SHA1 SAML) sont les plus sérieux : ce sont des **faiblesses de configuration par défaut** plutôt que des bugs — elles ne seront probablement jamais des CVE car conformes aux spécifications, mais créent une surface exploitable en cas d'erreur de configuration client.

**Remédiations supplémentaires recommandées :**
1. **N1** : imposer `S256` via client policy (`pkce-code-challenge-method=S256`) pour tous les clients publics — ne jamais accepter `plain` hors héritage contraint.
2. **N3** : encoder/neutraliser `error_description` provenant des IdP externes avant toute interpolation dans exception/log/UI.
3. **N6** : si Argon2 activé, paramètres ≥ 19 MiB / 2 itérations / 1 parallélisme (ligne directrice OWASP).
4. **N4/N5** : remplacer `new Random()`/`Math.random()` par `ThreadLocalRandom` (nommage threads) pour hygiène, et documenter qu'aucun usage crypto n'y est attaché.

---

## 8. Compte rendu complet — analyse multi-agents de toutes les lignes

**Méthode :** 6 agents d'analyse parallélisés, chacun responsable d'un périmètre, sur les **766 116 lignes Java** (main) + modules JS :
- **Agent 1** — Endpoints OAuth2/OIDC (RFC 6749/6750/7009/7662/9126)
- **Agent 2** — OIDC Core (nonce, hashes, session, logout, discovery)
- **Agent 3** — Tokens (rotation refresh, codes, DPoP, mTLS, offline)
- **Agent 4** — OAuth2 Security BCP RFC 9700 + client policies
- **Agent 5** — Sweep des modules non couverts (adapters, authz, rest, saml, scim, operator)
- **Agent 6** — Passe globale : patterns dangereux sur l'intégralité des lignes

### 8.1 Conformité OAuth 2.0 / OIDC — vérification exhaustive des recommandations

| Norme / recommandation | Statut | Preuve (code) |
|---|---|---|
| **RFC 6749 §3.1.2** : redirect_uri en matching exact | ✅ Conforme | `RedirectUtils.java:95-158` : matching exact string + schéma validé (http/https ou custom explicitement autorisé) |
| **RFC 6749 §10.5** : le client DOIT valider `state` | ✅ (côté client uniquement — serveur le reflète) | Le `state` est transporté de bout en bout sans interprétation par le serveur (comportement conforme) |
| **RFC 6749 / OIDC** : `nonce` obligatoire en OIDC implicit/hybrid | ✅ Conforme | `AuthorizationEndpointChecker.java:315-327` : erreur `INVALID_REQUEST` si `response_type` inclut `id_token` sans nonce (exception pure OAuth2 documentée) |
| **RFC 6750** : Bearer token | ✅ | `UserInfoEndpoint` : contrôle scope `openid`, vérification `not-before` utilisateur |
| **RFC 7009** : révocation de tokens | ✅ | `RevocationEndpoint` : validation client requise |
| **RFC 7662** : introspection | ✅ | `TokenIntrospectionEndpoint:125,167` : authentification client obligatoire, rejet des clients publics |
| **RFC 9126 (PAR)** : request_uri à usage unique | ✅ | `ParEndpoint:190-206` : `SingleUseObjectProvider`, durée de vie limitée, isolation par realm, `request_uri` interdit dans PAR |
| **RFC 9700 §2.1** : codes à usage unique + rotation des refresh tokens | ✅ | `AuthorizationCodeGrantType` : code consommé une fois ; `TokenManager:353` : limite de réutilisation du refresh token (`reuse exceeded` → révocation) |
| **RFC 9700 §2.1.1** : PKCE pour clients publics | ✅ disponible / ⚠️ non imposé | `PKCEEnforcerExecutor` (client policy) existe ; par défaut `plain` ET `S256` annoncés (`OIDCWellKnownProvider:93`) — **écart BCP** (cf. N1) |
| **RFC 9700 §2.2.1** : confidentialité du client secret | ✅ | Comparaison en temps constant (`MessageDigest.isEqual`, `ClientAdapter:234`), jamais journalisé |
| **RFC 9700 §2.4** : pas de credentials dans l'URL | ✅ | Token endpoint : POST form-encoded uniquement |
| **RFC 9700 §2.5** : éviter `response_type=token` (implicit) | ⚠️ Déprécié mais supporté | `DEFAULT_RESPONSE_TYPES_SUPPORTED` inclut encore `token` ; à désactiver par client policy |
| **RFC 9700 §2.6** : pas de ROPC (password grant) | ⚠️ Supporté | `ResourceOwnerPasswordCredentialsGrantType` présent ; à désactiver par client policy |
| **RFC 9700 §4.4.3 / 2.1.2** : redirect_uri en https | ⚠️ HTTP toléré | `RedirectUtils:136-158` : schéma `http` accepté (hors règles custom). À forcer par client policy en prod |
| **OIDC Core §3.1.3.7** : validation `iss`, `aud`, `exp`, `nonce` des ID tokens | ✅ | `TokenVerifier` : `RealmUrlCheck` (iss), `AudienceCheck` (aud), expiration, AZP |
| **OIDC Core §3.1.3.6 / 3.2.2 / 5.4** : `at_hash` / `c_hash` | ✅ générés | `TokenManager:1502-1503` : `at_hash` calculé pour hybrid flow ; HashUtils conforme (moitié gauche du hash) |
| **OIDC Core §3.1.2.1** : authentification du client au token endpoint | ✅ | `getClientAuthMethodsSupported` : secret basic/post, JWT, mTLS ; introspection authentifiée |
| **OIDC Core §12** : signature des ID tokens (`alg` ≠ none) | ✅ | `AuthenticationManager:1573-1583` : provider d'algorithme résolu, `alg=none` rejeté |
| **OIDC Discovery** : metadata complètes | ✅ | `OIDCWellKnownProvider:141-171` : tous les champs `*_supported` renseignés |
| **OIDC Back-Channel Logout (RFC 9436)** | ✅ | `LogoutEndpoint:583-619` : endpoint dédié, token signé obligatoire (CVE-2026-18569 corrigée) |
| **OIDC RP-Initiated Logout** | ✅ | `LogoutEndpoint:150-257` : `id_token_hint`/`client_id` requis avec `post_logout_redirect_uri`, cohérence client vérifiée (l.199-205) |
| **OIDC UserInfo** : scope openid obligatoire | ✅ | `UserInfoEndpoint:212` : rejet explicite `Missing openid scope` |
| **RFC 8705** : mTLS certificate-bound tokens | ✅ implémenté | `HolderOfKeyEnforcerExecutor`, claims `cnf`/`x5t#S256` dans `TokenManager` |
| **RFC 9449** : DPoP | ✅ implémenté | `DPoPUtil`, `DPoPBindEnforcerExecutor` : pre-of-possession avec vérification du header `DPoP` |
| **FAPI 1.0/2.0** | ✅ implémenté (opt-in) | Executors `PKCEEnforcer`, `HolderOfKey`, `ConfidentialClientAccept`, `IntentClientBindCheck` via client policies |
| **CIBA** | ✅ | Grants `ciba*` présents avec validators dédiés |
| **Token exchange (RFC 8693)** | ✅ | `StandardTokenExchangeProvider:312` : `offline_access` refusé en échange (bonne pratique) |

**Verdict conformité : ~85 %.** Les 4 écarts (PKCE plain admis, implicit flow supporté, ROPC supporté, redirect http toléré) sont des choix de compatibilité **neutralisables par client policies** — le BCP n'est pas appliqué par défaut mais tous les mécanismes d'application existent dans le code.

### 8.2 Nouveaux constats des agents 1-6 (au-delà de la section 7)

| # | Localisation | Constat | Gravité |
|---|---|---|---|
| **N8** | `adapters/saml/.../HttpClientBuilder.java:249,266,366` + `IDP.java:189` | **`disableTrustManager` dans l'adaptateur SAML** : option config → `PassthroughTrustManager` (accepte **tout** certificat) + `AllowAllHostnameVerifier`. Opt-in, mais une erreur de configuration de l'adaptateur désactive toute validation TLS vers l'IdP | **High (si activé)** — CWE-295 |
| **N9** | `operator/.../KeycloakClientBaseController.java:382` | Opérateur K8s : `NoopHostnameVerifier` activé conditionnellement quand le certificat ne couvre pas le hostname du service (cas TLS passthrough, cert leaf) — intention documentée, risque d'erreur de config admin | Medium — CWE-295 |
| **N10** | `services/.../cache/ComputedKey.java:34` | **MD5** pour les clés de cache de lookup IdP/clients. Non cryptographique (clé interne Infinispan), collision → entrée de cache erronée mais re-validée (l.37-41) → impact quasi nul | Info — CWE-327 (hygiène) |
| **N11** | `distribution/.../CopyDependencies.java:92` | MD5 dans un outil de build (somme de contrôle) | Info |
| **N12** | `authz/.../js/JSPolicyProvider.java:56` | `adapter.eval(context)` : évaluation de politiques **JavaScript côté serveur** — création admin requise, feature non activée par défaut | Medium (si activée) — CWE-94 |
| **N13** | `integration/client-cli/admin-cli/.../KcAdmV2EditCmd.java:133-137` | `ProcessBuilder("cmd","/c", editor + ...)` — l'éditeur vient de `EDITOR`/config locale : contrôle de `EDITOR` d'un compte = exécution de commande locale (l'attaquant contrôle déjà le compte) | Low (locale) — CWE-78 |
| **N14** | `quarkus/.../KeycloakMain.java:79` | `System.exit` proprement contourné (picocli) — vérifié sain | Info |

### 8.3 Zones couvertes par les agents et confirmées saines

- **Agent 1** : discovery complet et exact ; PAR à usage unique scellé par realm ; introspection protégée (rejet clients publics) ; userinfo avec contrôle scope + not-before.
- **Agent 2** : `at_hash`/`c_hash` générés selon la spec ; logout OIDC complet (front + back channel), `id_token_hint` ↔ `client_id` croisés ; backchannel logout signé obligatoirement.
- **Agent 3** : rotation des refresh tokens avec détection de réutilisation (`reuse exceeded`) ; DPoP et mTLS binding implémentés ; `offline_access` refusé en token exchange.
- **Agent 4** : `verifyRedirectUri` = matching exact, schémas whitelistés ; 20+ executors de client policy couvrant FAPI/BCP.
- **Agent 5** : modules `rest`, `saml`, `scim`, `docs`, `misc`, `skills` — aucun pattern dangereux en code main. Les `HostnameVerifier` permissifs trouvés sont tous dans la testsuite (normal) ou conditionnels (N8/N9).
- **Agent 6** : 0 secret codé en dur sur toute la base ; 0 TODO/FIXME sécurité en attente ; 0 requête SQL concaténée ; 0 `System.exit` incontrôlé ; les 4 `ProcessBuilder` sont analysés (2 service Windows contrôlés, 1 kcadm documenté en N13).

### 8.4 Synthèse générale de l'audit complet

| Catégorie | Nombre | Détail |
|---|---|---|
| CVE connues analysées | 29 | Toutes corrigées dans ce snapshot (post-26.8.1) |
| Constats statiques (sections 3.2) | 6 (F1-F6) | SHA-1 SAML/OTP, vault plaintext, Kerberos legacy, snapshot, CI |
| Constats approfondis (section 7) | 7 (N1-N7) | PKCE plain, timing, error_description, Random, Argon2, SHA-1 |
| Constats multi-agents (section 8) | 7 (N8-N14) | disableTrustManager adapter, NoopHostnameVerifier operator, MD5 cache, JS eval policy, ProcessBuilder kcadm |
| Recommandations normatives OAuth2/OIDC vérifiées | 27 | 23 conformes, 4 écarts neutralisables par configuration |
| Zones vérifiées saines | 30+ | XXE, LDAP, SQL, SSTI, cookies, brute force, conteneur, supply chain… |

**Score final révisé : 7,5 / 10 inchangé** — les nouveaux constats (N8-N14) sont tous conditionnels (opt-in, local ou fonctionnels) et ne changent pas la posture globale. Le verdict opérationnel reste : ne pas déployer le SNAPSHOT, durcir la configuration, imposer S256 + https + clients confidentiels via client policies, rester synchronisé avec upstream.

**Plan de remédiation consolidé (priorisé) :**
- **P0** : release stable ≥ 26.8.1 uniquement ; vault chiffré (keystore) obligatoire en prod.
- **P1** : client policy « BCP 9700 » : `PKCEEnforcer(S256)`, interdiction implicit + ROPC, https obligatoire sur redirect_uris ; désactiver `disableTrustManager`/`allowAnyHostname` dans tous les adaptateurs SAML déployés (N8).
- **P2** : SHA-256 au lieu de MD5 pour `ComputedKey` (contribution amont possible) ; remplacer `new Random()` par `ThreadLocalRandom` ; durcir Argon2 si activé.
- **Veille** : synchronisation hebdomadaire upstream + alerting sur `security-advisories` du dépôt officiel.
