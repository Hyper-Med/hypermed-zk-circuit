pragma circom 2.0.0;

// Import the optimized ZK cryptographic primitives
include "../circomlib/circuits/eddsaposeidon.circom";
include "../circomlib/circuits/poseidon.circom";
include "../circomlib/circuits/comparators.circom";

// Secure Insurance Claim Circuit
// @description: This circuit allows a patient to prove to an insurance company that they have a specific medical condition, 
// without revealing the actual condition. The doctor provides a cryptographic signature on the diagnosis, 
// and the insurance company can verify it without learning the patient's private medical data.
template SecureInsuranceClaim() {
    // Public inputs
    // This is what the circuit(insurance agency) sees and uses to verify the claim
    signal input requiredCondition; 
    signal input doctorPubKey[2]; // The hospital's official BabyJubJub Public Key (X, Y)

    // Private Inputs 
    // the data Patient keeps hidden
    signal input secretPatientCondition; 
    
    // The EdDSA cryptographic signature components from the Doctor
    signal input doctorSignatureR8[2];
    signal input doctorSignatureS;

    // @dev: Hash the Medical Data
    // We hash the condition using Poseidon (a ZK-friendly hash)
    component hasher = Poseidon(1);
    hasher.inputs[0] <== secretPatientCondition;
    signal msgHash <== hasher.out;

    // @dev: Cryptographic Integrity Check
    // This proves the Doctor ACTUALLY signed THIS specific diagnosis
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== doctorPubKey[0];
    sigVerifier.Ay <== doctorPubKey[1];
    sigVerifier.R8x <== doctorSignatureR8[0];
    sigVerifier.R8y <== doctorSignatureR8[1];
    sigVerifier.S <== doctorSignatureS;
    sigVerifier.M <== msgHash;

    // @dev: Eligibility Check
    // This proves the diagnosed condition matches the insurance requirement
    component eq = IsEqual();
    eq.in[0] <== secretPatientCondition;
    eq.in[1] <== requiredCondition;

    // @notice: The circuit will crash if the conditions don't match
    eq.out === 1;
}

// Instantiate the component. 
// The Insurance company ONLY sees the required condition and the Doctor's public key.
component main {public [requiredCondition, doctorPubKey]} = SecureInsuranceClaim();