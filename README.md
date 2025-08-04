# `open-org-license-scanner`

This tool helps you regularly scan your organisation's repositories for dependencies with problematic licenses, and flags them out to you / your policy team for review.


As the scanner will also have read-permissions for all repositories it is installed on, the scanner is **designed to be cloned as a template** and maintained by any organisation that requires it to further mitigate supply-chain attacks.

This tool does **not** prevent new installations of problematic dependencies. If you wish to configure rules to enforce this, see [Enforce Dependency Review](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/enforcing-dependency-review-across-an-organization).

## Installation
### Requirements
- Review `src/index.ts` and ensure the code has not been tampered with.
- Enable the `dependency-graph` feature on all repositories which will be scanned. This tool makes use of Github's Software Bill Of Materials (SBOM) API endpoint.

### Installation Steps

1. Navigate to Organization Settings > Developer Settings, and click 'New Github App'
2. Fill in the following fields:
    * GitHub App name (This can be any name you want)
    * Homepage URL (This can be any URL you want)
    * Webhooks: `Disable`
    * **Repository Permissions**
        * Contents: `Read-only`
        * Metadata: `Read-only`
        * Issues: `Read, Write`
    * Where can this GitHub App be installed: `Only on this account`
3. Click 'Create Github App'
4. You will be redirected to your app's settings page. Note down the following information:
    1. App ID
    2. App Name
    3. Scroll down to Private Keys > 'Generate a Private Key'. This will download a `.pem` file to your current computer. **Make sure that you perform this operation on a secure computer, as whoever gains access to this key can impersonate the application.**
5. Navigate to 'Install App' under the left sidebar.
6. Click 'Install' on your organisation's entry, then click 'Install' again on the next screen.
7. You will be brought to the app's installation page. View the URL of the page, e.g: `https://github.com/organizations/xxxxxxx/settings/installations/yyyyyyyy`, and copy down the `yyyyyyyy` portion. This is your app's **Installation ID.**
8. Clone this repository as a template, under your Github Organisation. While creating the new repository, take note of your Organisation's URL, and the new repository's name.
9. Navigate to the new repository's settings and create the following:
    1. Github Repository Secrets:
        - `GH_APP_PRIVATE_KEY`: The contents of the `.pem` file you generated earlier.
        - `GH_ORG_INSTALLATION_ID`: The Installation ID of your app on your organisation.
        - `SLACK_WEBHOOK_URL` (optional): If you have a Slack channel you would like the tool to post notifications to, enter its webhook here.
    2. Github Repository Variables
        - `GH_APP_ID`: The App ID of your Github App
        - `GH_APP_REPOSITORY_NAME`: The new repository's name
        - `GH_ORG_URL`: The URL of your organisation, e.g: `https://github.com/organizations/xxxxxxx`
10. Installation complete! 🎉

## Configuration
Under `config.yml`, you can set two properties:

### `blacklist`
Example:
```yaml
...
blacklist:
  - CC0-1.0
  - CC-BY-SA-4.0
  - ...
...
```
A collection of licenses that specify what the scanner looks out for.

### `ignorePackagesRegex`
Example:
```yaml
...
ignorePackagesRegex:
  - eslint
  - .*myInternalTooling.*
  - ...
...
```
A collection of regexes. If a package name matches ANY of the regexes, they will be ignored by the scanner.

## Running the Scanner
The scanning script is triggered as a Github Workflow Action, specified under `.github/workflows/run-scanner.yml`. By default, scans are triggered upon pushes to `develop`, manual dispatches, and once every day using the `cron` scheduler feature. You can modify this behaviour by directly editing the action's `yaml` file.

## Debugging
The script's debug logs can be viewed by turning on [debug mode](https://github.blog/changelog/2022-05-24-github-actions-re-run-jobs-with-debug-logging/).