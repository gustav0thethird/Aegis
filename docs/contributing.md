# Contributing

To contribute to the Aegis project, please follow the guidelines outlined below.

## Getting Started

1. **Fork the Repository**: Start by forking the Aegis repository to your own GitHub account.

2. **Clone Your Fork**: Clone your forked repository to your local machine:
   ```bash
   git clone https://github.com/your-username/aegis.git
   cd aegis
   ```

3. **Set Up the Environment**: Install the required dependencies. You can find the dependencies listed in `requirements.txt` and `requirements-dev.txt`. Use the following command:
   ```bash
   pip install -r requirements.txt -r requirements-dev.txt
   ```

4. **Create a Branch**: Create a new branch for your feature or bug fix:
   ```bash
   git checkout -b your-feature-branch
   ```

## Making Changes

1. **Code Style**: Ensure your code adheres to the project's coding standards. You can use `ruff` for linting:
   ```bash
   ruff check aegis/ tests/
   ```

2. **Testing**: Write tests for your changes and run the existing tests to ensure everything works as expected:
   ```bash
   pytest tests/ -v --tb=short
   ```

3. **Documentation**: Update the documentation as necessary to reflect your changes.

## Submitting Changes

1. **Commit Your Changes**: Commit your changes with a clear and concise commit message:
   ```bash
   git commit -m "Add your descriptive commit message here"
   ```

2. **Push to Your Fork**: Push your changes to your forked repository:
   ```bash
   git push origin your-feature-branch
   ```

3. **Create a Pull Request**: Navigate to the original Aegis repository and create a pull request from your feature branch. Provide a detailed description of your changes and why they are necessary.

## Continuous Integration

The project uses GitHub Actions for continuous integration. Your pull request will trigger the CI workflows, which include linting and testing. Ensure that all checks pass before your pull request can be merged.

## Code Review

Once your pull request is submitted, it will be reviewed by the maintainers. Be open to feedback and make any necessary changes.

## Additional Notes

- For security scans, the project uses Bandit and Gitleaks. Ensure that your code does not introduce any vulnerabilities.
- Regularly check for updates to dependencies using Dependabot.

Thank you for contributing to Aegis!
