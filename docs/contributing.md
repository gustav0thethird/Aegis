# Contributing

Thank you for your interest in contributing to the Aegis project. We welcome contributions from the community. Please follow the guidelines below to ensure a smooth contribution process.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](../CODE_OF_CONDUCT.md). Please read it to understand the expectations for behavior.

## How to Contribute

1. **Fork the Repository**: Start by forking the repository on GitHub. This will create a copy of the repository under your GitHub account.

2. **Clone Your Fork**: Clone your forked repository to your local machine using:
   ```
   git clone https://github.com/your-username/aegis.git
   ```

3. **Create a Branch**: Create a new branch for your feature or bug fix:
   ```
   git checkout -b feature/your-feature-name
   ```

4. **Make Changes**: Implement your changes in the codebase. Ensure that your code adheres to the project's coding standards.

5. **Run Tests**: Before submitting your changes, run the tests to ensure everything works as expected. You can run the tests using:
   ```
   pytest tests/
   ```

6. **Commit Your Changes**: Commit your changes with a clear and concise commit message:
   ```
   git commit -m "Add feature: your feature description"
   ```

7. **Push Your Changes**: Push your changes to your forked repository:
   ```
   git push origin feature/your-feature-name
   ```

8. **Create a Pull Request**: Navigate to the original repository on GitHub and create a pull request from your branch. Provide a clear description of your changes and why they should be merged.

## Guidelines for Contributions

- **Code Quality**: Ensure your code is clean, well-documented, and follows the project's style guide. Use `ruff` for linting:
  ```
  ruff check aegis/ tests/
  ```

- **Testing**: Write tests for any new features or bug fixes. Ensure that all existing tests pass.

- **Documentation**: If your changes affect the documentation, please update it accordingly.

- **Commit Messages**: Use clear and descriptive commit messages. Follow the format:
  ```
  type(scope): subject
  ```
  Example:
  ```
  feat(api): add new endpoint for user authentication
  ```

## Reporting Issues

If you encounter any bugs or have feature requests, please report them by opening an issue in the repository. Provide as much detail as possible to help us understand the problem.

## License

By contributing to this project, you agree that your contributions will be licensed under the project's [LICENSE](LICENSE). 

Thank you for your contributions to Aegis!
