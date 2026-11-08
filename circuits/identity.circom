pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
/*
* Spécification fonctionnelle du Circuit Universel HumanVault (Selective
Disclosure)
* Transposable directement en ConstraintSynthesizer<F> sous Arkworks (src/zkp.rs)
:
* - Mode 0 (Seuil >=) : ex. (currentTimestamp - birthTimestamp) >= 18 ans, ou
Salaire >= 1000 €
* - Mode 1 (Égalité ===) : ex. Pays_Residence_ISO === 250
*/
template HumanVaultUniversalIdentity() {
 // --- ENTRÉES PRIVÉES (Restent strictement en RAM locale) ---
 signal input secretKey; // Clé K (256 bits) issue du Fuzzy Commitment
biométrique
 signal input attrBirthTimestamp; // Attribut 0 : Date de naissance (UNIX)
 signal input attrCountryIso; // Attribut 1 : Code Pays ISO (ex: 250)
 signal input attrSalaryNet; // Attribut 2 : Revenu / Salaire certifié
(ex: 2450)
 signal input selectedAttrValue; // Valeur de l'attribut interrogé pour cette
transaction
 // --- ENTRÉES PUBLIQUES (Vérifiées par le serveur partenaire) ---
 signal input publicAnchor; // Ancre = Poseidon(secretKey, attr0, attr1,
attr2)
 signal input predicateMode; // 0 = Comparaison de seuil (>=), 1 = Égalité
stricte (===)
 signal input thresholdOrTarget; // Seuil requis (ex: 1000 pour salaire, 250
pour pays, etc.)
 // --- SORTIE PUBLIQUE ---
 signal output isValid;
 // 1. Contrôle d'intégrité de l'Ancre Publique multi-attributs
 component hasher = Poseidon(4);
 hasher.inputs[0] <== secretKey;
 hasher.inputs[1] <== attrBirthTimestamp;
 hasher.inputs[2] <== attrCountryIso;
 hasher.inputs[3] <== attrSalaryNet;
 publicAnchor === hasher.out;
 // 2. Évaluation du prédicat (Seuil >= OU Égalité ===)
 component checkGte = GreaterEqThan(64);
 checkGte.in[0] <== selectedAttrValue;
 checkGte.in[1] <== thresholdOrTarget;
 component checkEq = IsEqual();
 checkEq.in[0] <== selectedAttrValue;
 checkEq.in[1] <== thresholdOrTarget;
 // Sélection arithmétique du mode : (1 - mode)*GTE + mode*EQ
 signal gteBranch;
 signal eqBranch;
 gteBranch <== (1 - predicateMode) * checkGte.out;
 eqBranch <== predicateMode * checkEq.out;
 isValid <== gteBranch + eqBranch;
 isValid === 1;
}
component main {public [publicAnchor, predicateMode, thresholdOrTarget]} =
HumanVaultUniversalIdentity();