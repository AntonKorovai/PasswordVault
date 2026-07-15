import time
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import numpy as np

def run_benchmark():

    iterations = 100
    print(f"STARTING CRYPTOGRAPHIC BENCHMARK ({iterations} iterations)")

    print("Running RSA (2048 bit) test...")
    
    start = time.perf_counter()
    for _ in range(iterations):
        _ = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_gen_time = (time.perf_counter() - start) / iterations

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub_key = rsa_key.public_key()
    message = b"Test message for Challenge-Response simulation"
    
    rsa_signature = rsa_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )


    start = time.perf_counter()
    for _ in range(iterations):
        _ = rsa_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    rsa_sign_time = (time.perf_counter() - start) / iterations

    start = time.perf_counter()
    for _ in range(iterations):
        rsa_pub_key.verify(
            rsa_signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    rsa_verify_time = (time.perf_counter() - start) / iterations


    print("Running ECC (Ed25519) test...")
    
    start = time.perf_counter()
    for _ in range(iterations):
        _ = ed25519.Ed25519PrivateKey.generate()
    ecc_gen_time = (time.perf_counter() - start) / iterations

    ecc_key = ed25519.Ed25519PrivateKey.generate()
    ecc_pub_key = ecc_key.public_key()
    
    ecc_signature = ecc_key.sign(message)

    start = time.perf_counter()
    for _ in range(iterations):
        _ = ecc_key.sign(message)
    ecc_sign_time = (time.perf_counter() - start) / iterations

    start = time.perf_counter()
    for _ in range(iterations):
        ecc_pub_key.verify(ecc_signature, message)
    ecc_verify_time = (time.perf_counter() - start) / iterations


    print("Processing results")
    
    labels = ['Key Generation\n(New User)', 'Digital Signature\n(Client Login)', 'Verification\n(Server Check)']


    rsa_times = [rsa_gen_time * 1000, rsa_sign_time * 1000, rsa_verify_time * 1000]
    ecc_times = [ecc_gen_time * 1000, ecc_sign_time * 1000, ecc_verify_time * 1000]

    x = np.arange(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    
    bars1 = ax.bar(x - width/2, rsa_times, width, label='RSA 2048-bit', color='#e74c3c')
    bars2 = ax.bar(x + width/2, ecc_times, width, label='ECC Ed25519', color='#2ecc71')

    ax.set_ylabel('Average execution time (Milliseconds)')
    ax.set_title('Performance Analysis: RSA vs Elliptic Curves (Zero-Knowledge Architecture)', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    ax.set_yscale('log') 
    ax.set_ylim(0.01, max(rsa_times) * 5)
    ax.grid(axis='y', linestyle='--', alpha=0.7)


    def add_labels(bars):
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height * 1.2,
                    f"{height:.2f} ms",
                    ha='center', va='bottom', fontweight='bold', fontsize=9)

    add_labels(bars1)
    add_labels(bars2)

    plt.tight_layout()
    plt.savefig('benchmark_chart_complete.png', dpi=300)
    print("Chart generated and saved as 'benchmark_chart_complete.png'.")
    
    plt.show()

if __name__ == "__main__":
    run_benchmark()