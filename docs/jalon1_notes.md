# Jalon 1 — Notes de travail (brouillon du rapport)

## Objectif

Remplacer l'extraction simulée (Hamming(7,4)) par un véritable code correcteur d'erreurs (BCH ou Reed-Solomon), afin de dériver une clé cryptographique stable à partir de la biométrie (`face_master_vector`).

## 1. Contexte

### Code de Gray
- Codage des **numéros de case** (index de quantification) en bits, utilisé pour pouvoir appliquer le fuzzy commitment.
- Propriété : deux cases voisines (`idx`, `idx + 1`) ont des codes de Gray qui diffèrent d'**un seul bit**.
- Conséquence : un petit bruit sur un flottant, qui le fait glisser d'une case, ne produit qu'**un bit faux** dans `w`, que le code correcteur peut corriger. En binaire classique, un tel glissement peut inverser jusqu'à 6 bits.
  - Exemple : `31 = 0b00011111` et `32 = 0b00100000` diffèrent de 6 bits en binaire classique.

### Codes correcteurs
- **Hamming(7,4)** : corrige **1 erreur par bloc de 7 bits** (pas assez efficace en pratique).
- **BCH / RS** : codes correcteurs plus puissants que Hamming.

### Critère des « 10 % »
- `w` : vecteur quantifié de **64 bits** (8 dimensions × 8 bits).
- 10 % de 64 bits = 6,4 → correction de **t = 7** bits erronés.
- La clé K (32 octets = 256 bits) n'est jamais bruitée : c'est elle qu'on reconstruit.

### Flux
- **Enrôlement** : vecteur biométrique (flottants) → quantification + code de Gray (`w`) → encodage (Hamming / RS / BCH)
  → clé secrète K + helper data **public** = (offsets, masque, tag = H(K)).
- **Authentification** : nouveau vecteur biométrique → quantification + Gray (`w'`) → décodage de (`w'` ⊕ masque)
  → clé K' (reconstruite au bit près) → comparaison en temps constant de H(K') avec le tag.

## 2. Choix et décisions (validés avec le client)

| Décision | Valeur | Source |
|---|---|---|
| Capacité de correction | t = 7 (arrondi supérieur de 6,4) | mail du client du 11/11 |
| Nature du bruit | 10 % des bits de `w` inversés (distance de Hamming), à des positions quelconques | mail du client du 11/11 |
| Clé K | déterministe, dérivée de la biométrie | mail du client du 11/11 |
| Objectif | K reconstruite au bit près dans **100 %** des cas pour e ≤ 7 (e = nombre de bits erronés) | mail du client du 11/11 |

## 3. Ligne de base : Hamming(7,4)

**Conditions de mesure** : mock officiel `Face_Mock_Enroll.json` ; e bits de `w` inversés à des positions distinctes tirées au hasard parmi 64 ; 1 000 essais par ligne ; PRNG `StdRng`, graine 42 ; test `test_fuzzy_commitment_k_inversed_bits`.

**Modèle théorique** : une dimension est correctement décodée si elle reçoit au plus 1 erreur dans ses bits 0 à 6 (le bit 7 est ignoré par le décodeur). Nombre de tirages favorables parmi C(64, e) :

```
favorables(e) = Σ_j  C(8, j) × C(8, e−j) × 7^(e−j)
                (j = nombre d'erreurs tombées sur des bits 7)
```

| e (bits inversés) | Mesuré | Théorique |
|---|---|---|
| 0 | 100,0 % | 100,0 % |
| 1 | 100,0 % | 100,0 % |
| 2 | 91,7 % | 91,7 % |
| 3 | 74,4 % | 76,3 % |
| 4 | 58,4 % | 57,2 % |
| 5 | 39,2 % | 38,1 % |
| 6 | 20,1 % | 22,3 % |
| 7 | 13,0 % | 11,3 % |
| 8 | 4,0 % | 4,9 % |

Aucune mauvaise clé n'a été acceptée (0 sur 9 000 essais) : les échecs sont tous détectés par le tag.

**Conclusion** : pour 7 bits inversés, environ 11 à 13 % de réussite. Hamming(7,4) ne tient pas le critère de 100 %.

## 4. RS ou BCH : que choisir ?

### Reed-Solomon
- Fonctionne sur des **symboles** (par exemple un octet = 8 bits).
- 1 bit erroné ou 8 bits erronés dans le même octet = **une seule** erreur de symbole.
- Problème : 7 bits erronés dispersés sur 7 symboles = 7 erreurs de symbole. Il faudrait n − k ≥ 2 × 7 = 14 symboles de redondance, alors que `w` ne fait que 8 octets.

| RS sur les 64 bits de `w` | n (symboles) | k max pour t = 7 |
|---|---|---|
| symboles de 8 bits | 8 | impossible |
| symboles de 6 bits | ≈ 11 | impossible |
| symboles de 4 bits (RS étendu) | 16 | 2 symboles = 8 bits |

### BCH binaire
- Fonctionne directement sur les **bits** : corrige t bits faux n'importe où dans un bloc de n bits.
- 7 bits dispersés = 7 erreurs, couvertes par t = 7.
- À COMPLÉTER après lecture.

**Conclusion** : on choisit BCH.

## 5. BCH(63, 24, 7)

- Longueur : n = 2^m − 1 avec m = 6, soit **n = 63** (corps GF(2⁶)). 64 n'est pas une longueur possible pour un BCH binaire primitif.
- **k = 24** bits de message ; les 63 − 24 = 39 autres bits sont de la redondance (degré du polynôme générateur). Plus t est grand, plus il faut de redondance : t = 6 → k = 30 ; t = 7 → k = 24. k borne l'entropie de K.
- **t = 7** erreurs corrigeables (critère).

### Passer de 64 bits à 63

| Option | Principe | Message | Remarque |
|---|---|---|---|
| Exclusion d'un bit | le code couvre 63 des 64 bits ; le bit restant n'est pas protégé et une erreur sur lui est ignorée | 24 bits | sans perte si le bit exclu est toujours nul |
| BCH étendu (64, 24) | ajout d'un bit de parité globale au mot de 63 bits | 24 bits | corrige 7 erreurs et détecte à coup sûr 8 erreurs |
| Raccourci depuis BCH(127, 78) | 63 bits de message fixés à 0 et non transmis | 15 bits | moins bon |

- Choix : À COMPLÉTER (bit exclu et justification).

### Crates BCH examinées

| Crate | Licence | BCH(63, 24, 7) | Verdict |
|---|---|---|---|
| `syndrome` 0.6.1 | MIT | non (GF(2⁸) uniquement) | rejetée |
| `code-rs` 1.0.1 | MIT | non (code fixe BCH(63, 16, 11)) | rejetée |
| `ecc-codes` 0.1.0 | MIT / Apache-2.0 | pas de BCH | rejetée |
| `comnum-fec` 0.3.1 | MIT / Apache-2.0 | oui (générique) | plan B (pas `no_std`) |

**Décision** : implémentation maison ; `comnum-fec` en plan B.

## 6. Schéma retenu (étape 4)

À COMPLÉTER.
