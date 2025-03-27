import numpy as np
import matplotlib.pyplot as plt

# Global variable for maximum iterations (you can change this value as needed)
max_iter = 30

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
    # Define the list of matrix sizes to test: 2x2, 3x3, ..., up to 10x10.
    matrix_sizes = list(range(2, 11))
    
    # Store iteration results (similarity percentages) for plotting
    iterations = np.arange(0, max_iter + 1)  # from X_0 to X_max_iter
    similarity_data = {}

    for n in matrix_sizes:
        # Generate a random n x n matrix (scaled up to avoid too small numbers)
        A = np.random.rand(n, n) * 10
        # Compute the true inverse of A
        A_inv = np.linalg.inv(A)
        # Compute Frobenius norm of A for the initial guess
        norm_A_F = np.linalg.norm(A, 'fro')
        # Initial guess: X0 = A^T / (||A||_F^2)
        X0 = (A.T) / (norm_A_F**2)

        # Print the random matrices
        np.set_printoptions(precision=2, suppress=True)
        print(f"\n---- Matrix size: {n}x{n} ----")
        print("\nMatrix A:")
        print(A)
        print("\nTrue inverse of A:")
        print(A_inv)
        
        # Run Newton iteration up to max_iter iterations (X_0 ... X_max_iter)
        X_list = newton_inverse_iteration(A, X0, max_iter=max_iter)
        
        # Compute similarity percentages for each iteration
        similarities = [similarity_percentage(X, A_inv) for X in X_list]
        similarity_data[f"{n}x{n}"] = similarities

    # Plot all curves on one graph with different colors and labels.
    plt.figure(figsize=(10, 7))
    color_map = plt.get_cmap('tab10', len(matrix_sizes))
    for i, n in enumerate(matrix_sizes):
        label = f"{n}x{n}"
        sims = similarity_data[label]
        plt.plot(iterations, sims, marker='o', linestyle='-', color=color_map(i), label=label)

    plt.title("Newton's Method for Inverse: Similarity to True Inverse")
    plt.xlabel("Iteration (k)")
    plt.ylabel("Similarity (%)")
    plt.ylim(0, 105)
    plt.legend(title="Matrix Size")
    plt.grid(True)
    plt.show()

if __name__ == "__main__":
    main()
