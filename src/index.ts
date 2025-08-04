import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { env } from "node:process";
import { App } from "octokit";
import packageJson from "package-json";
import Queue from "queue";
import { parse } from "yaml";

const appId = env.GH_APP_ID;
const privateKey = env.GH_APP_PRIVATE_KEY;
const orgUrl = env.GH_ORG_URL;
const appRepoName = env.GH_APP_REPOSITORY_NAME;
const installationId = env.GH_ORG_INSTALLATION_ID;
const slackWebhookUrl = env.SLACK_WEBHOOK_URL;
const debug = env.RUNNER_DEBUG === "1";

// [0] - Types

interface PackageData {
	name: string;
	isTransitiveDep: boolean;
	version: string;
	resolveMode: string;
	license: string;
}
interface OrganisationRepos {
	repo: string;
	relationshipMap: Map<string, string>;
	packages: PackageData[];
}

type MappedPackageData = Pick<OrganisationRepos, "repo"> &
	Pick<PackageData, "isTransitiveDep" | "resolveMode">;

type PackageDataMap = Map<
	string,
	Map<string, Map<string, MappedPackageData[]>>
>;

// [0] - Utility functions

const resolveLicenseFromNPM = async (pkgName: string, version?: string) =>
	packageJson(pkgName, {
		fullMetadata: true,
		version,
	})
		.then(({ license }) => ({
			resolveMode: "npmCurrVer",
			license: license,
		}))
		.catch(() =>
			packageJson(pkgName, {
				fullMetadata: true,
			})
				.then(({ license }) => ({
					resolveMode: "npmLatestVer",
					license: license,
				}))
				// ignore all non-NPM packages
				.catch(() => ({ resolveMode: "failed", license: "non-NPM" })),
		) as Promise<{
		resolveMode: string;
		license: string;
	}>;

// [1] - Fetch and use configs

const configFile = readFileSync("./config.yml", "utf8");

let licenseBlacklist = [];
let ignorePackagesRegex = [] as string[];
try {
	const configs = parse(configFile);
	licenseBlacklist = configs.blacklist as string[];
	ignorePackagesRegex = configs.ignorePackagesRegex as string[];
} catch (_) {
	throw new Error("failed to parse configs!");
}

const ignoreRegexes = ignorePackagesRegex.map(
	(regexpStr) => new RegExp(regexpStr),
);

const initLogger = (debug: boolean) => (msg: unknown) => {
	if (debug) console.info(msg);
};
const debugLog = initLogger(debug);

debugLog("Configuration for run:");
debugLog(`licenseBlacklist: ${licenseBlacklist}`);
debugLog(`ignorePackagesRegex: ${ignorePackagesRegex}`);
debugLog(`debug: ${debug}`);

// [2] - Authenticate Github App

if (!appId || !privateKey || !installationId)
	throw new Error("missing credentials!");

if (!licenseBlacklist) throw new Error("no blacklist provided!");

if (!appRepoName) throw new Error("no app repository name provided!");

if (!orgUrl) throw new Error("no organisation github URL provided!");
const orgName = new URL(orgUrl).pathname.replace("/", "");

// initialize github app credentials
const app = new App({
	appId,
	privateKey: privateKey.replace(/\\n/gm, "\n"),
});

// get installation scoped access
const octokit = await app.getInstallationOctokit(
	Number.parseInt(installationId),
);

// check authentication works before proceeding
const { data: appData } = await octokit.request("/app");
if (!appData) throw new Error("authentication failed");

debugLog(`authenticated as ${appData.name}`);

// [3] - Scan organisation for repos

// retrieve all repos available on the installation
const orgRepos = await octokit
	.paginate("GET /orgs/{org}/repos", {
		org: orgName,
		type: "all",
	})
	.then((repos) => repos.filter((repo) => repo.name !== ".github"));

if (orgRepos.length === 0)
	throw new Error(`failed to retrieve repos for org ${orgName}`);

const nRepos = orgRepos.length;

// [4] - Filter out all archived repos, as SBOM is not available for them

const { archived, valid: validOrgRepos } = orgRepos.reduce(
	(arrs, orgRepo) => {
		if (orgRepo.archived) {
			debugLog(`Skipping repo ${orgRepo.name}, reason: archived`);
			arrs.archived.push(orgRepo);
		} else arrs.valid.push(orgRepo);

		return arrs;
	},
	{
		archived: [] as typeof orgRepos,
		valid: [] as typeof orgRepos,
	},
);

const nArchived = archived.length;

// [5] - Get problems for all available repositories

let nScanned = 0;
let nFailed = 0;
let nAffected = 0;

// use maps to quickly organise raw data
const blacklistMap = new Map() as PackageDataMap;
const noLicenseMap = new Map() as PackageDataMap;
const insertPkgIntoMap = (
	repo: string,
	pkg: PackageData,
	map: PackageDataMap,
) => {
	const { name, version, license, resolveMode, isTransitiveDep } = pkg;
	if (!map.has(name)) {
		map.set(name, new Map<string, Map<string, MappedPackageData[]>>());
	}
	if (!map.get(name)?.has(license)) {
		map.get(name)?.set(license, new Map<string, MappedPackageData[]>());
	}
	if (!map.get(name)?.get(license)?.has(version)) {
		map.get(name)?.get(license)?.set(version, []);
	}
	map
		.get(name)
		?.get(license)
		?.get(version)
		?.push({ repo, resolveMode, isTransitiveDep });
};

// util function to parse maps back into arrays for convenience
const arraifyMap = (map: PackageDataMap) =>
	Array.from(map, ([k, v]) => ({
		name: k,
		licenses: Array.from(v, ([k, v]) => ({
			license: k,
			versions: Array.from(v, ([k, v]) => ({
				version: k,
				repos: v.sort((a, b) => a.repo.localeCompare(b.repo)),
			})).sort((a, b) => a.version.localeCompare(b.version)),
		})).sort((a, b) => a.license.localeCompare(b.license)),
	})).sort((a, b) => a.name.localeCompare(b.name));

// create a job queue to orchestrate sbom api calls
const taskQueue = new Queue({
	concurrency: 2, // according to best practices, should be sequential
});

// load all promises into the job queue
validOrgRepos.forEach(({ owner, name }) =>
	taskQueue.push(() =>
		// [5a] - get sbom from repository
		octokit
			.request("GET /repos/{owner}/{repo}/dependency-graph/sbom", {
				owner: owner.login,
				repo: name,
			})
			.catch(() => {
				// fail gracefully if we can't retrieve sboms for a particular repo
				nFailed++;
				console.error(`failed to retrieve sboms for repo ${name}`);
				return undefined;
			})
			.then(async (res) => {
				if (!res) return undefined;
				const { relationships, packages } = res.data.sbom;

				// [5b] - get transitive dependency status

				// generate relationship map for the current repo
				const relationshipMap = (relationships ?? []).reduce(
					(map, { spdxElementId, relatedSpdxElement }) => {
						if (spdxElementId && relatedSpdxElement && !map.has(spdxElementId))
							map.set(spdxElementId, relatedSpdxElement);
						return map;
					},
					new Map<string, string>(),
				);

				// locate and filter out the product from its dependencies
				const { deps, mainSpdxId } = packages.reduce(
					({ deps, mainSpdxId }, pkg) => {
						if (!pkg.SPDXID) pkg.SPDXID = "NOTFOUND";

						if (pkg.versionInfo !== "main") deps.push(pkg);
						else mainSpdxId = pkg.SPDXID;
						return {
							deps,
							mainSpdxId,
						};
					},
					{ deps: [] as typeof packages, mainSpdxId: "" },
				);

				// [5c] - resolve package licenses on a best effort basis

				const resolvedPackages = await Promise.all(
					deps
						// get unique packages
						.reduce(
							(state, current) => {
								if (current.name && !state.uniqueDepNames.has(current.name)) {
									state.uniqueDepNames.add(current.name);
									state.uniqueDeps.push(current);
								}
								return state;
							},
							{
								uniqueDepNames: new Set<string>(),
								uniqueDeps: [] as typeof deps,
							},
						)
						.uniqueDeps.map(
							async ({
								name,
								versionInfo: version,
								licenseConcluded,
								SPDXID,
							}) => {
								const { resolveMode, license } = licenseConcluded
									? {
											resolveMode: "explicit",
											license: licenseConcluded,
										}
									: // no need to ratelimit this api endpoint
										await resolveLicenseFromNPM(name as string, version);

								// check if dependency is transitive or direct
								const isTransitiveDep =
									relationshipMap.get(SPDXID ?? "") !== mainSpdxId;

								return {
									name,
									isTransitiveDep,
									version,
									license,
									resolveMode,
								} as PackageData;
							},
						),
				);

				return {
					repo: name,
					packages: resolvedPackages,
				};
			})
			// unexpected error occured
			.catch((err) => {
				nFailed++;
				console.error(err);
			})
			.then((res) => {
				if (res) {
					// log on successful operation
					nScanned++;
					debugLog(
						`Scanned repo ${nScanned + nFailed + nArchived} / ${nRepos}: ${name}`,
					);
				}

				return res;
			})
			.then((res) => {
				// [5d] - update maps with results on successful completion
				if (!res?.packages) return;

				let affected = false;
				const { repo, packages } = res;
				packages
					.filter(
						(pkg) => !ignoreRegexes.some((regExp) => regExp.test(pkg.name)),
					)
					.forEach((pkg) => {
						if (pkg.license === "Unknown") {
							insertPkgIntoMap(repo, pkg, noLicenseMap);
							affected = true;
						} else if (licenseBlacklist.includes(pkg.license)) {
							insertPkgIntoMap(repo, pkg, blacklistMap);
							affected = true;
						}
					});

				if (affected) nAffected++;
			}),
	),
);

// start job queue
const problems = await taskQueue.start().then(() => {
	// job is done now
	debugLog(
		`Scanned: ${nScanned} / Archived: ${nArchived} / Failed: ${nFailed}, out of ${nRepos} total repositories.\n\nResults:\n`,
	);

	return {
		blacklistPkgs: arraifyMap(blacklistMap),
		noLicensePkgs: arraifyMap(noLicenseMap),
	};
});

const { blacklistPkgs, noLicensePkgs } = problems;

// [6] - Process problems to a human readable format

// format arrays into markdown for readability
let nTransitiveDeps = 0;
let nDirectDeps = 0;
const reposWithDirectDeps = new Set();
const generateMDFromPkgs = (pkgsCategory: "blacklisted" | "missing") =>
	`### Dependencies with ${pkgsCategory} licenses\n` +
	`| Package Name | License | Repositories Affected |\n` +
	`| --- | --- | --- |\n` +
	`${(pkgsCategory === "blacklisted" ? blacklistPkgs : noLicensePkgs)
		.map(({ name, licenses }) =>
			licenses
				.map(({ license, versions }) => ({
					license,
					versions: versions
						.map(
							({ version, repos }) =>
								`@ ${version}:<br>${repos
									.map(({ repo, resolveMode, isTransitiveDep }) => {
										// get package transitivity statistics
										if (isTransitiveDep) nTransitiveDeps++;
										else {
											nDirectDeps++;
											reposWithDirectDeps.add(repo);
										}

										const repoLink = `  - [\`\`\`${repo}\`\`\`](${orgUrl}/${repo})`;

										const transitiveDepTag = isTransitiveDep
											? "indirect"
											: "direct";

										const resolveTag =
											resolveMode !== "failed" && resolveMode !== "explicit"
												? ` (${resolveMode})`
												: "";

										return `${repoLink} (${transitiveDepTag})${resolveTag}`;
									})
									.join(",<br>")}`,
						)
						.join(",<br>"),
				}))
				.map(({ license, versions }, idx) =>
					idx < 1
						? `| \`\`\`${name}\`\`\` | ${license} | ${versions} |`
						: `| | ${license} | ${versions} |`,
				)
				.join("\n"),
		)
		.join("\n")}\n\n` +
	`Please ${pkgsCategory === "blacklisted" ? "remove" : "review"} these dependencies.`;

const generateIssueBody = () =>
	`\`\`\`org-license-scanner\`\`\` has detected ${nDirectDeps} direct, ${nTransitiveDeps} transitive dependency problems:`;

// [7] Export problems to the github app's repository under issues.

const outputComponents = [];
if (blacklistPkgs.length > 0) {
	outputComponents.push(generateMDFromPkgs("blacklisted"));
}
if (noLicensePkgs.length > 0) {
	outputComponents.push(generateMDFromPkgs("missing"));
}
const mdProblems = outputComponents.join("\n\n");

if (mdProblems === "") {
	debugLog("No problems detected.");
} else {
	debugLog(mdProblems);

	// [7a] - Get github app's repository context

	const appRepo = orgRepos.filter((repo) => repo.name === appRepoName);
	if (appRepo.length < 1)
		throw new Error(
			"this github app's repository is not within the organisation!",
		);
	const appRepoCtx = {
		owner: appRepo[0].owner.login,
		repo: appRepoName,
	};

	// [7b] - Create / Update issue managed by the app

	const issue_number = await octokit
		// we don't expect this repository to have any user created issues,
		// therefore there should only be one issue from the bot in the response
		.request("GET /repos/{owner}/{repo}/issues", {
			...appRepoCtx,
			creator: `${appData.slug}[bot]`,
		})
		.catch(() => {
			console.error(`failed to retrieve issues for the gh app's repository`);
			return undefined;
		})
		.then((res) => {
			if (!res) return undefined;
			const { data: issues } = res;

			// get the first issue created by the application
			return issues.length > 0 ? issues[0].number : undefined;
		})
		.then(async (issue_number) =>
			// if no issue exists, create one; else, update it.
			issue_number
				? issue_number
				: await octokit
						.request("POST /repos/{owner}/{repo}/issues/", {
							...appRepoCtx,
							title: "Org License Scanner Results",
							body: generateIssueBody(),
							issue_number,
						})
						.catch(() => {
							console.error(
								`failed to create / update issue in the gh app's repository`,
							);
							return undefined;
						})
						.then((res) => res?.data.number as number),
		);

	// [7c] - Create / Update result comment managed by the bot

	const existingComment = issue_number
		? await octokit
				.request("GET /repos/{owner}/{repo}/issues/{issue_number}/comments", {
					...appRepoCtx,
					issue_number,
					sort: "created",
				})
				.catch(() => {
					console.error(
						`failed to retrieve comments for issue ${issue_number}`,
					);
					return undefined;
				})
				.then(async (res) => {
					if (!res) return undefined;
					const { data: comments } = res;

					// try to get first comment in the issue
					return comments.length > 0 ? comments[0] : undefined;
				})
		: undefined;

	// [7d] - Check for diffs; if none, then skip the rest of the update steps

	const hasDiffs = (a: string, b: string) =>
		createHash("md5").update(a).digest("base64") !==
		createHash("md5").update(b).digest("base64");

	if (existingComment?.body && !hasDiffs(existingComment.body, mdProblems)) {
		console.log("No differences found, skipping comment export step.");
	} else {
		// [7e] - Otherwise, update the relevant comments, and send a link to Slack

		await octokit.request("PATCH /repos/{owner}/{repo}/issues/{issue_number}", {
			...appRepoCtx,
			title: "Org License Scanner Results",
			body: generateIssueBody(),
			issue_number,
		});

		const githubResultsUrl = await (existingComment
			? octokit.request(
					"PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}",
					{
						...appRepoCtx,
						comment_id: existingComment.id,
						body: mdProblems,
					},
				)
			: octokit.request(
					"POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
					{
						...appRepoCtx,
						issue_number,
						body: mdProblems,
					},
				)
		)
			.catch(() => {
				console.error(
					`failed to create / update comment in the gh app's repository`,
				);
				return undefined;
			})
			.then((res) => {
				console.log(
					res
						? "Exported results to the github app's repository."
						: "Results failed to export.",
				);

				return res?.data.html_url;
			});

		// [8] - Update slack webhook with link to results

		const slackBlockMsg = {
			blocks: [
				{
					type: "header",
					text: {
						type: "plain_text",
						text: "🚨 New Dependency Licensing Issues Found",
						emoji: true,
					},
				},
				{
					type: "section",
					text: {
						type: "mrkdwn",
						text: "`org-license-blacklist-scanner` has detected new license problems for review.",
					},
				},
				{
					type: "divider",
				},
				{
					type: "section",
					fields: [
						{
							type: "mrkdwn",
							text: `*Blacklisted Packages:*\n${blacklistPkgs.length}`,
						},
						{
							type: "mrkdwn",
							text: `*Packages Missing Licenses:*\n${noLicensePkgs.length}`,
						},
						{
							type: "mrkdwn",
							text: `*Direct Dependency Problems:*\n${
								reposWithDirectDeps.size > 0
									? Array.from(reposWithDirectDeps)
											.sort()
											.map((repo) => `\n- ${repo}`)
											.join("")
									: "None."
							}`,
						},
						{
							type: "mrkdwn",
							text: `*Transitive Dependency Problems:*\n${nTransitiveDeps}`,
						},
						{
							type: "mrkdwn",
							text: `*Repositories Affected:*\n${nAffected} / ${nRepos} (${Math.round((nAffected / nRepos) * 100)}%)`,
						},
					],
				},
				{
					type: "actions",
					elements: [
						{
							type: "button",
							text: {
								type: "plain_text",
								emoji: true,
								text: "View In Github",
							},
							style: "primary",
							url: githubResultsUrl,
						},
					],
				},
				{
					type: "context",
					elements: [
						{
							type: "mrkdwn",
							text: `Alert triggered at \`${new Date().toISOString()}\``,
						},
					],
				},
			],
		};

		if (!githubResultsUrl) {
			debugLog("No Github link available, skipping Slack notification.");
		} else if (!slackWebhookUrl) {
			debugLog("No Slack webhook link available, skipping Slack notification.");
		} else {
			debugLog("Notified Slack.");
			fetch(new URL(slackWebhookUrl), {
				method: "POST",
				body: JSON.stringify(slackBlockMsg),
			});
		}
	}
}
