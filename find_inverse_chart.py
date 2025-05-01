import numpy as np
import matplotlib.pyplot as plt

# Global parameters: maximum number of iterations and number of samples
max_iter = 30
num_samples = 100

def newton_inverse_iteration(A, X0, max_iter=max_iter):
    """
    Perform Newton's iteration to approximate A^{-1}.
    Returns a list of approximations [X0, X1, ..., X_max_iter].
    """
    n = A.shape[0]
    I = np.eye(n)
    X = X0.copy()
    results = [X0.copy()]
    for _ in range(max_iter):
        X = X @ (2 * I - A @ X)
        results.append(X.copy())
    return results

def similarity_percentage(X, A_inv):
    """
    Compute the similarity percentage between X and the true inverse A_inv.
    100% means X is exactly A_inv.
    """
    diff = np.linalg.norm(X - A_inv, 'fro') / np.linalg.norm(A_inv, 'fro')
    return (1.0 - diff) * 100.0

def main():
    # Matrix sizes to test: from 2x2 to 20x20
    matrix_sizes = list(range(2, 21))
    
    # x-axis: from X_0 to X_max_iter
    iterations = np.arange(0, max_iter + 1)
    similarity_data = {}

    for n in matrix_sizes:
        sum_sims = np.zeros(max_iter + 1)
        for sample_idx in range(num_samples):
            # Generate random matrix, compute true inverse and initial guess
            A = np.random.rand(n, n) * 10
            A_inv = np.linalg.inv(A)
            norm_A_F = np.linalg.norm(A, 'fro')
            X0 = A.T / (norm_A_F**2)

            # Print only the first sample's matrix and its inverse for small n
            if sample_idx == 0 and n <= 5:
                np.set_printoptions(precision=2, suppress=True)
                print(f"\n---- Matrix size: {n}x{n} (sample 1 of {num_samples}) ----")
                print("\nMatrix A:")
                print(A)
                print("\nTrue inverse of A:")
                print(A_inv)

            # Perform Newton iteration
            X_list = newton_inverse_iteration(A, X0, max_iter)
            
            # Accumulate similarity for each iteration
            sims = [similarity_percentage(X, A_inv) for X in X_list]
            sum_sims += np.array(sims)

        # Average similarity across all samples
        avg_sims = sum_sims / num_samples
        similarity_data[f"{n}x{n}"] = avg_sims

    # Print table of iterations needed to reach ≥90% similarity
    print(f"\n{'Matrix Size':>10} | {'Iters to ≥90%':>14}")
    print("-" * 27)
    for size, sims in similarity_data.items():
        idx = next((i for i, sim in enumerate(sims) if sim >= 90), None)
        iters = idx if idx is not None else "N/A"
        print(f"{size:>10} | {str(iters):>14}")

    # Plotting
    plt.figure(figsize=(10, 7))
    color_map = plt.get_cmap('tab10', len(matrix_sizes))
    for i, n in enumerate(matrix_sizes):
        label = f"{n}x{n}"
        plt.plot(iterations, similarity_data[label],
                 marker='o', linestyle='-', color=color_map(i), label=label)

    # 90% highlight line
    plt.axhline(y=90, color='red', linestyle='--', linewidth=1)

    plt.title("Newton's Method for Inverse: Average Similarity over Random Matrices")
    plt.xlabel("Iteration (k)")
    plt.ylabel("Similarity (%)")
    plt.ylim(0, 105)
    plt.legend(title="Matrix Size")
    plt.grid(True)
    plt.annotate(
        "k₀: Initial guess from $A^T / ||A||_F^2$",
        xy=(0, 0),
        xytext=(0, -35),
        textcoords='offset points',
        fontsize=12,
        ha='center',
    )
    plt.show()

    # Matrix Size vs Iters to ≥90% plot 
    sizes = matrix_sizes
    iters_to_90 = []
    for n in sizes:
        sims = similarity_data[f"{n}x{n}"]
        idx = next((i for i, sim in enumerate(sims) if sim >= 90), None)
        iters_to_90.append(idx if idx is not None else np.nan)

    plt.figure(figsize=(8, 5))
    plt.plot(sizes, iters_to_90, marker='o', linestyle='-')
    plt.title("Iterations to Reach ≥90% Similarity vs Matrix Size")
    plt.xlabel("Matrix Dimension (n)")
    plt.ylabel("Iterations to ≥90%")
    plt.grid(True)
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    main()
