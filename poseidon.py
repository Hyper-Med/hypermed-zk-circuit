import argparse
from pathlib import Path
import subprocess
import sys
import shutil
import subprocess
import math
import re
import pyfiglet
import time
import secrets
import os
from pathlib import Path

def write_boilerplate_circuit(file_path):
    boilerplate = """\
pragma circom 2.0.0;

// This is an example of how to import libraries from circomlib.
// In this case, we're using the Poseidon hashing function from circomlib.

include "../circomlib/circuits/poseidon.circom";

// This is just a boilerplate circuit that demonstrates how to use Poseidon hashing in Circom.
// You can use this as a template for building circuits that require hashing operations.

template PoseidonHashExample() {
    // Define inputs to the circuit
    // In this case, we're using an array of 2 inputs for the Poseidon hash function.
    signal input inputs[2];  
    signal output hash;

    // Create a Poseidon component with 2 inputs.
    // Poseidon is a cryptographic hash function.
    component poseidon = Poseidon(2);

    // Map the inputs to the Poseidon component
    poseidon.inputs[0] <== inputs[0];
    poseidon.inputs[1] <== inputs[1];

    // The hash output is assigned from the Poseidon component
    hash <== poseidon.out;
}

// This is the main component, which instantiates the PoseidonHashExample template
component main = PoseidonHashExample();
"""
    with open(file_path, "w") as f:
        f.write(boilerplate)
    print(f"[+] Wrote Poseidon hash boilerplate to {file_path}")


def run_cmd(cmd, cwd=None):
    print(f">> Running: {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        details = f"Error: {result.stderr.strip()}" if result.stderr else "No additional details."
        sys.exit(f"Command failed: {cmd}\n{details}")
    return result.stdout 

def resolve_tool_path(tool_name):
    path = shutil.which(tool_name)
    if path:
        return path

    cargo_bin_tool = Path.home() / ".cargo" / "bin" / tool_name
    if cargo_bin_tool.exists():
        return str(cargo_bin_tool)

    return None 

def is_tool_installed(tool_name):
    return resolve_tool_path(tool_name) is not None

def get_tool_or_exit(tool_name):
    tool_path = resolve_tool_path(tool_name)
    if not tool_path:
        sys.exit(f"{tool_name} is not installed or not available on PATH.")
    return tool_path

def ensure_local_bin_paths():
    cargo_bin = str(Path.home() / ".cargo" / "bin")
    if not Path(cargo_bin).exists():
        return

    current_path = os.environ.get("PATH", "")
    path_parts = current_path.split(os.pathsep) if current_path else []
    if cargo_bin not in path_parts:
        os.environ["PATH"] = f"{cargo_bin}{os.pathsep}{current_path}" if current_path else cargo_bin

def install_circom():
    print("[+] Installing circom from source...")

    if not Path("circom").exists():
        run_cmd("git clone https://github.com/iden3/circom.git")

    # Build and install
    circom_dir = "circom"
    run_cmd("cargo build --release", cwd=circom_dir)
    run_cmd("cargo install --path ./circom", cwd=circom_dir)

    
def setup_circuit_env():
    print("[+] Checking environment...")

    tools = ["git", "cargo", "circom", "snarkjs", "node", "npm",]
    missing = []

    for tool in tools:
        if is_tool_installed(tool):
            print(f"[+] {tool} is installed.")
        else:
            print(f"[X] {tool} is NOT installed.")
            if(tool == "git"):
                print("[!] Git not found. Please install git manually from https://git-scm.com/downloads to PROCEED")
                sys.exit(1)
            if(tool == "cargo"):
                print("[!] cargo and rust not installed. Please install cargo+rust manually from https://doc.rust-lang.org/cargo/getting-started/installation.html to PROCEED")
                sys.exit(1)
            if(tool == "node"):
                print("[!] Node.js is not installed. Please install Node.js manually from https://nodejs.org/ to PROCEED")
                sys.exit(1)
            missing.append(tool)
    
    if(len(missing) > 0):
        for i in range(0,len(missing)):
            if(missing[i] == "circom"):
                print("[*] Installing circom....")
                install_circom()
                
            if(missing[i] == "snarkjs"):
                print("[*] Installing snarkjs....")
                run_cmd("npm i -g snarkjs")
        

    circomlib_dir = Path("circomlib")
    if not circomlib_dir.exists():
        print("[+] Pulling circomlib for libraries...")
        run_cmd("git clone https://github.com/iden3/circomlib.git")
    else:
        print("[*] circomlib already exists.")


    circuits_dir = Path("circuits")
    if not circuits_dir.exists():
        circuits_dir.mkdir()
        print("[+] Created 'circuits' directory.")
    else:
        print("[+] 'circuits' directory already exists.")

    default_circuit = circuits_dir / "circuit1.circom"
    
    if not default_circuit.exists():
        print("[*] Creating a sample circuit to start with...")
        time.sleep(3)
        default_circuit.touch()
        print("[+] Created 'circuit1.circom'.")
        write_boilerplate_circuit(default_circuit)
    else:
        print("[+] 'circuit1.circom' already exists.")

        print("[+] circom circuit environment ready.\n")

    print("\n Next Steps: Setting up SNARK environment")
    print("  1. Compile your circuit:")
    print()
    print("  2. Generate trusted setup (e.g. Powers of Tau):")
    print()
    print("  3. Generate proving and verification keys:")
    print()
    print("  4. Export verifier contract (optional for Solidity use):")
    print()
    print(" You can now write inputs and test your circuit with snarkjs!")


def compile_circuit(circuit_name):
    print("[*] Compiling circuit...")
    circom_bin = resolve_tool_path("circom")
    if not circom_bin:
        sys.exit("circom is not installed or not available on PATH. Run --circuit-setup first.")

    run_cmd(f'"{circom_bin}" circuits/{circuit_name}.circom --r1cs --wasm --sym')
    print("[+] Circuit compiled.\n")


def get_constraint_count(circuit_name):
    r1cs_file = f"{circuit_name}.r1cs"
    print(f"[*] Getting constraint count from {r1cs_file}...")
    snarkjs_bin = get_tool_or_exit("snarkjs")
    output = run_cmd(f'"{snarkjs_bin}" r1cs info {r1cs_file}')
    
    match = re.search(r'# of Constraints:\s+(\d+)', output)
    if match:
        constraints = int(match.group(1))
        print(f"[i] Found {constraints} constraints.")
        return constraints
    else:
        raise ValueError("Could not extract constraint count.")


def init_trusted_setup(circuit_name):
    constraints = get_constraint_count(circuit_name)
    m = max(2, math.ceil(math.log2(max(1, constraints * 2))))
    print(f"[i] Calculated m = ceil(log2(2 * {constraints})) = {m}")

    snarkjs_bin = get_tool_or_exit("snarkjs")

    ptau_0000 = f"pot{m}_0000.ptau"
    ptau_0001 = f"pot{m}_0001.ptau"
    ptau_final = f"pot{m}_final.ptau"
    
    if os.path.exists(ptau_final):
        print(f"[+] Setup already established: {ptau_final} exists.")
    else:
        random_entropy = secrets.token_hex(32)

        print(f"[*] Running Powers of Tau ceremony with m = {m}")
        cmd1 = f'"{snarkjs_bin}" powersoftau new bn128 {m} {ptau_0000} -v'
        print(f">> Running: Creating universal trusted setup for circuit size upto {m}")
        time.sleep(3)
        run_cmd(cmd1)

        cmd2 = f'"{snarkjs_bin}" powersoftau contribute {ptau_0000} {ptau_0001} --entropy={random_entropy}'
        print(f">> Running: Adding randomness to make it trusted")
        time.sleep(3)
        run_cmd(cmd2)
        
        cmd3 = f'"{snarkjs_bin}" powersoftau prepare phase2 {ptau_0001} {ptau_final} -v'
        print(f">> Running: Finalizing and preparing for phase 2(circuit-specific proving key generation)")
        time.sleep(3)
        run_cmd(cmd3)

    final_zkey = f"{circuit_name}_final.zkey"
    if os.path.exists(final_zkey):
        print(f"[!] Proving key already exists: {final_zkey}")
    else:
        random_entropy = secrets.token_hex(32)

        cmd4 = f'"{snarkjs_bin}" groth16 setup {circuit_name}.r1cs {ptau_final} {circuit_name}_0000.zkey'
        print(f">> Running: Setting up proving key")
        time.sleep(3)
        run_cmd(cmd4)
        
        cmd5 = f'"{snarkjs_bin}" zkey contribute {circuit_name}_0000.zkey {final_zkey} --entropy={random_entropy}'
        print(f">> Running: Contributing randomness to the proving key")
        time.sleep(3)
        run_cmd(cmd5)
        
    cmd6 = f'"{snarkjs_bin}" zkey export verificationkey {final_zkey} verification_key.json'
    print(f">> Running: creating verification key")
    time.sleep(3)
    run_cmd(cmd6)

    print(f"\n[+] Trusted setup complete for circuit_size(m) upto {m}.\n")
    
    
def generate_proof(circuit_name):
    file = Path("./input.json")
    if not os.path.exists("input.json"):
        file.touch()
    else:
        print("[*] Please fill in the circuit inputs in json format in input.json")
        time.sleep(3)
        
        print("[*] Generating witness...")
        try:
            subprocess.run(f"node {circuit_name}_js/generate_witness.js {circuit_name}_js/{circuit_name}.wasm input.json witness.wtns", 
                            shell=True, check=True)
            print("[+] Witness generated successfully...")
        except subprocess.CalledProcessError as e:
            print(f"[-] Exiting system - Failed due to: {e}")
            exit(1)
            
        try:
            print("[*] Proof generation started...")
            time.sleep(3)
            subprocess.run(f"snarkjs groth16 prove {circuit_name}_final.zkey witness.wtns proof.json public.json", 
                            shell=True, check=True)
            print("[+] proof generated successfully...")
            
        except subprocess.CalledProcessError as e:
            print("[-] failed: exiting system")
            exit(1)
      

def verify_proof():
    file_path = Path("./proof.json")
    if not os.path.exists("./proof.json"):
        print("[!] proof.json not found...please write your proof in proof.json with the proof you want to verify")
        file_path.touch()
        
    print("[*] Proof verification started...make sure to modify proof.json")
    time.sleep(3)
    subprocess.run(f"snarkjs groth16 verify verification_key.json public.json proof.json", shell=True, check=True)
    print("[+] Proof verification successfull")
    
    
def export_verifier(sol_file="Verifier.sol"):
    run_cmd(f"snarkjs zkey export solidityverifier circuit_final.zkey {sol_file}")

def print_banner():
    banner = pyfiglet.figlet_format("POSEIDON", font="slant")
    print(banner)
    print(">> zk-SNARK Automation Tool")
    print()
    print("+---------------------------------------------------+")
    print("| @Version: 1.0.0                                   |")
    print("| @Author: Dave                                     |")
    print("| @GitHub: https://github.com/dave1725/poseidon.git |")
    print("+---------------------------------------------------+")
    print()

def main():
    ensure_local_bin_paths()
    print_banner()
    parser = argparse.ArgumentParser(description="zk-SNARK automation tool")

    parser.add_argument("--circuit-setup", action="store_true", help="setup the circuit environment to kickstart development")
    parser.add_argument("--yes", action="store_true", help="skip confirmation prompt")
    parser.add_argument("--compile-only", metavar="circuit_name", type=str, help="Only compile the circuit (advanced users)")
    parser.add_argument("--init-setup", metavar="circuit_name",type=str, help="Compile, run trusted setup ceremony, setup proving key - all ready for zkProof generation (beginners)")
    parser.add_argument("--prove", metavar="circuit_name", type=str, help="to generate zkProof with the circuit compiled and trusted setup")
    parser.add_argument("--verify", action="store_true", help="to verify the zkProof generated")

    args = parser.parse_args()

    if args.compile_only:
        circuit_name = args.compile_only
        compile_circuit(circuit_name)
    elif args.init_setup:
        circuit_name = args.init_setup
        compile_circuit(circuit_name)
        init_trusted_setup(circuit_name)
    elif args.circuit_setup:
        setup_circuit_env()
    elif args.prove:
        
        circuit_name = args.prove
        if not args.yes:
            ch = input("Filled in ? (Y|N): ").lower()
            if ch != 'y':
                print("[!] Please fill input.json and try again.")
        else:   
            generate_proof(circuit_name)
            
    elif args.verify:
        verify_proof()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
