#!/usr/bin/env node
'use strict';

/*
======================================================================
Name: Conditional Access Impact Matrix
Description: This script helps solve a frequent problem: the lack of
             visibility of the exact Entra ID Conditional Access policies
             assigned to each user.
Author: Jasper Baes (https://www.linkedin.com/in/jasper-baes/)
Enhancements: Safety, CLI, caching, formatting by Burak's Copilot
Published: January 20, 2023 (enhanced 2025-11-05)
Dependencies: axios, msal-node, fs, json-2-csv, dotenv
======================================================================
*/

// version of the tool
global.currentVersion = '2025.11.05'

// Declare libraries
require('dotenv').config();
const axios = require('axios');
const msal = require('@azure/msal-node'); // kept because helper uses it
const fs = require('fs');
const converter = require('json-2-csv');
const helper = require('./helper');

// Console colors
global.fgColor = {
    FgRed: "\x1b[31m",
    FgGreen: "\x1b[32m",
    FgYellow: "\x1b[33m",
    FgBlue: "\x1b[34m",
    FgMagenta: "\x1b[35m",
    FgCyan: "\x1b[36m",
    FgGray: "\x1b[90m",
}
global.colorReset = "\x1b[0m"

// Simple process-wide safety nets
process.on('unhandledRejection', (reason) => {
    console.error(`\n [${fgColor.FgRed}X${colorReset}] Unhandled rejection:`, reason);
    process.exit(1);
});
process.on('uncaughtException', (err) => {
    console.error(`\n [${fgColor.FgRed}X${colorReset}] Uncaught exception:`, err);
    process.exit(1);
});

function printHeader() {
    console.log(`\n${fgColor.FgCyan} ## Conditional Access Impact Matrix ## ${colorReset}${fgColor.FgGray}v${currentVersion}${colorReset}`);
    console.log(` ${fgColor.FgGray}Part of the Conditional Access Blueprint - https://jbaes.be/Conditional-Access-Blueprint${colorReset}`);
    console.log(` ${fgColor.FgGray}Created by Jasper Baes - https://github.com/jasperbaes/Conditional-Access-Matrix${colorReset}`);
}

function printHelp() {
    console.log(`
${fgColor.FgCyan}Conditional Access Impact Matrix${colorReset}
Usage:
  node index.js [options]

Options:
  -t, --type <member|guest>       Limit user scope to member or guest users
  -l, --limit <number>            Limit to first N users
  -g, --group <groupObjectId>     Only include users that are member of this group
      --include-report-only       Include report-only CA policies
      --include-disabled          Include disabled CA policies
      --policy "<regex>"          Only include CA policies whose displayName matches regex
      --compare <file.json>       Compare current run with previous JSON export
      --output <basename>         Basename for output files (default: YYYY-MM-DD-CA-Impact-Matrix)
      --format <csv|json|both>    Output format (default: both)
  -h, --help                      Show this help

Examples:
  node index.js --include-report-only --policy "Block.*Legacy"
  node index.js -t member -l 100 --output MyTenant-CA-Matrix --format csv
`);
}

async function init() {
    printHeader();

    // Help
    if (process.argv.some(p => ['-h', '--help', '/?'].includes(p.toLowerCase()))) {
        printHelp();
        process.exit(0);
    }

    await helper.onLatestVersion(); // polite version check (non-fatal if it fails)

    // Set global variables
    global.tenantID = process.env.TENANTID;
    global.clientSecret = process.env.CLIENTSECRET;
    global.clientID = process.env.CLIENTID;
    // global.thumbprint = process.env.THUMBPRINT  // still in development

    if (!global.tenantID || !global.clientID || !global.clientSecret) {
        console.error(` ${fgColor.FgRed}ERROR${colorReset}: Missing required environment variables. Ensure TENANTID, CLIENTID, CLIENTSECRET are set.`);
        process.exit(1);
    }

    global.scriptParameters = process.argv;

    const token = await helper.getToken(); // get access token

    if (token?.accessToken) {
        console.log(`\n [${fgColor.FgGreen}✓${colorReset}] Connected to tenant '${tenantID}'`);
        await calculate(token.accessToken, tenantID);
    } else {
        console.error(` [${fgColor.FgRed}X${colorReset}] Failed to acquire access token`);
        process.exit(1);
    }
}

init().catch(err => {
    console.error(`\n [${fgColor.FgRed}X${colorReset}] Fatal:`, err);
    process.exit(1);
});

/**
 * Main calculation pipeline.
 */
async function calculate(accessToken) {
    // Compose filter for CA policies
    console.log(` [${fgColor.FgGray}i${colorReset}] Fetching Conditional Access policies...`);

    // Default: enabled only
    const includeReportOnly = scriptParameters.some(param => ['--include-report-only'].includes(param.toLowerCase()));
    const includeDisabled   = scriptParameters.some(param => ['--include-disabled'].includes(param.toLowerCase()));
    const policyRegexIndex  = scriptParameters.findIndex(param => ['--policy'].includes(param.toLowerCase()));
    const policyRegexStr    = (policyRegexIndex !== -1 && policyRegexIndex + 1 < scriptParameters.length) ? scriptParameters[policyRegexIndex + 1] : null;

    let stateFilters = [`state eq 'enabled'`];
    if (includeReportOnly) stateFilters.push(`state eq 'enabledForReportingButNotEnforced'`);
    if (includeDisabled)   stateFilters.push(`state eq 'disabled'`);

    let url = `/v1.0/policies/conditionalAccessPolicies?$filter=${encodeURIComponent(stateFilters.join(' or '))}`;

    let conditionalAccessPolicies = await safeGetAll(accessToken, url, 'Conditional Access Policies');
    if (!conditionalAccessPolicies) process.exit(1);

    // Optional regex filter
    if (policyRegexStr) {
        try {
            const re = new RegExp(policyRegexStr, 'i');
            conditionalAccessPolicies = conditionalAccessPolicies.filter(p => re.test(p.displayName || ''));
        } catch (e) {
            console.error(` ${fgColor.FgRed}ERROR${colorReset}: Invalid regex for --policy: ${policyRegexStr}`);
            process.exit(1);
        }
    }

    console.log(` [${fgColor.FgGreen}✓${colorReset}] ${conditionalAccessPolicies.length} Conditional Access policies in scope`);

    conditionalAccessPolicies.sort((a, b) => {
        const an = (a.displayName || '').toLowerCase();
        const bn = (b.displayName || '').toLowerCase();
        if (an < bn) return -1;
        if (an > bn) return 1;
        return 0;
    });

    // Array of CA policy display names only
    const conditionalAccessPoliciesNames = conditionalAccessPolicies.map(policy => policy.displayName);

    // Fetch all users
    console.log(` [${fgColor.FgGray}i${colorReset}] Fetching users...`);
    // Using beta to keep parity with original script (jobTitle, accountEnabled present in v1.0 too)
    let users = await safeGetAll(accessToken, `/beta/users?$select=userPrincipalName,displayName,jobTitle,id,accountEnabled,userType`, 'Users');
    if (!users) process.exit(1);
    console.log(` [${fgColor.FgGreen}✓${colorReset}] ${users.length} users found`);

    // Type filter
    const typeIndex = scriptParameters.findIndex(param => ['-t', '--type'].includes(param.toLowerCase()));
    if (typeIndex !== -1 && typeIndex + 1 < scriptParameters.length) {
        const typeValue = (scriptParameters[typeIndex + 1] || '').toLowerCase();
        if (['member', 'members'].includes(typeValue)) {
            users = users.filter(user => user.userType === 'Member');
        } else if (['guest', 'guests'].includes(typeValue)) {
            users = users.filter(user => user.userType === 'Guest');
        } else {
            console.log(` ${fgColor.FgRed}ERROR${colorReset}: parameter -t or --type '${typeValue}' should be 'member' or 'guest'`);
            process.exit(1);
        }
        console.log(` [${fgColor.FgGreen}✓${colorReset}] Limiting user scope to the ${users.length} ${typeValue} users`);
    }

    // Limit filter
    const limitIndex = scriptParameters.findIndex(param => ['-l', '--limit'].includes(param.toLowerCase()));
    if (limitIndex !== -1 && limitIndex + 1 < scriptParameters.length) {
        const limitValueRaw = scriptParameters[limitIndex + 1];
        const limitValue = parseInt(limitValueRaw, 10);
        if (Number.isNaN(limitValue) || limitValue <= 0) {
            console.log(` ${fgColor.FgRed}ERROR${colorReset}: parameter -l or --limit '${limitValueRaw}' must be a positive integer`);
            process.exit(1);
        }
        users = users.slice(0, limitValue);
        console.log(` [${fgColor.FgGreen}✓${colorReset}] Limiting user scope to first ${limitValue} users`);
    }

    // Output settings
    const outIndex = scriptParameters.findIndex(param => ['--output'].includes(param.toLowerCase()));
    const outBase = (outIndex !== -1 && outIndex + 1 < scriptParameters.length) ? scriptParameters[outIndex + 1] : `${new Date().toISOString().slice(0, 10)}-CA-Impact-Matrix`;

    const fmtIndex = scriptParameters.findIndex(param => ['--format'].includes(param.toLowerCase()));
    const format = (fmtIndex !== -1 && fmtIndex + 1 < scriptParameters.length) ? (scriptParameters[fmtIndex + 1] || '').toLowerCase() : 'both';
    const outputCSV  = ['both', 'csv'].includes(format);
    const outputJSON = ['both', 'json'].includes(format);

    if (!outputCSV && !outputJSON) {
        console.log(` ${fgColor.FgRed}ERROR${colorReset}: --format must be one of csv|json|both`);
        process.exit(1);
    }

    console.log(` [${fgColor.FgGray}i${colorReset}] Generating matrix...`);
    const totalUsers = users.length;

    // Optional group filter (skip users not in the group)
    const groupIndex = scriptParameters.findIndex(param => ['-g', '--group'].includes(param.toLowerCase()));
    const groupValue = (groupIndex !== -1 && groupIndex + 1 < scriptParameters.length) ? scriptParameters[groupIndex + 1] : null;

    // Cache for subgroup expansions across the whole run (speeds up recursion)
    // Map<groupId, Set<groupId>>
    const subgroupCache = new Map();

    // Results
    const resultObj = [];

    // For each user
    for (let [index, user] of users.entries()) {
        // Fetch group memberships
        let groups = [];
        try {
            groups = await helper.getAllWithNextLink(accessToken, `/v1.0/users/${user.id}/memberOf?$select=id`);
        } catch (e) {
            console.log(`\n [${fgColor.FgYellow}!${colorReset}] Warning: failed to fetch groups for ${user.userPrincipalName}: ${e?.message || e}`);
            groups = [];
        }
        const groupList = (groups || []).map(g => g.id).filter(Boolean);

        // Optional: only continue if user is in provided group
        if (groupValue && !groupList.includes(groupValue)) {
            // Update progress and skip
            const progress = ((index + 1) / totalUsers) * 100;
            process.stdout.clearLine(0);
            process.stdout.cursorTo(0);
            process.stdout.write(` [${fgColor.FgGray}i${colorReset}] Progress: ${progress.toFixed(2)}% (${totalUsers - (index + 1)} user(s) remaining)`);
            continue;
        }

        // Base row
        const row = {
            user: (user.displayName || '').replace(/[,;]+/g, ''), 
            upn: (user.userPrincipalName || '').replace(/[,;]+/g, ''), 
            job: (user.jobTitle || '').replace(/[,;]+/g, ''),
            external: !!(user.userPrincipalName && user.userPrincipalName.includes('#EXT#@')),
            enabled: user.accountEnabled
        };

        // For each CA policy, compute inclusion
        for (const policy of conditionalAccessPolicies) {
            const included = await calculateIncluded(policy, user, groupList, accessToken, subgroupCache);
            // Create a clean, stable column name (no commas/semicolons)
            const colName = (policy.displayName || '').replace(/[,;]+/g, ' ');
            row[colName] = included;
        }

        resultObj.push(row);

        // Progress
        const progress = ((index + 1) / totalUsers) * 100;
        process.stdout.clearLine(0);
        process.stdout.cursorTo(0);
        process.stdout.write(` [${fgColor.FgGray}i${colorReset}] Progress: ${progress.toFixed(2)}% (${totalUsers - (index + 1)} user(s) remaining)`);
    }

    process.stdout.write(`\n`);
    console.log(` [${fgColor.FgGreen}✓${colorReset}] ${resultObj.length} users processed`);

    // Output
    try {
        if (outputCSV) {
            const csv = await converter.json2csv(resultObj, {
                // force schema: user, upn, job, external, enabled, then policies (dynamic)
                expandArrayObjects: true
            });
            const csvName = `${outBase}.csv`;
            fs.writeFileSync(csvName, csv);
            console.log(` [${fgColor.FgGreen}✓${colorReset}] '${csvName}' saved in current directory`);
        }

        if (outputJSON) {
            await helper.exportJSON(resultObj, `${outBase}.json`);
            console.log(` [${fgColor.FgGreen}✓${colorReset}] '${outBase}.json' saved in current directory`);
        }
    } catch (error) {
        console.log(` [${fgColor.FgRed}X${colorReset}] ${fgColor.FgRed}ERROR${colorReset}: Something went wrong converting/saving output`);
        console.log(`\n ${error} \n`);
    }

    // Compare
    try {
        if (scriptParameters.some(param => ['--compare'].includes(param.toLowerCase()))) {
            const idx = process.argv.indexOf('--compare');
            if (idx !== -1 && idx < process.argv.length - 1) {
                const compareFile = process.argv[idx + 1];
                console.log(` [${fgColor.FgGray}i${colorReset}] Comparing with ${compareFile}...`);
                const fileContent = JSON.parse(fs.readFileSync(`./${compareFile}`, 'utf-8'));
                await helper.compare(fileContent, resultObj);
            }
        }
    } catch (error) {
        console.log(` [${fgColor.FgRed}X${colorReset}] ${fgColor.FgRed}ERROR${colorReset}: Could not compare. Check if the file exists in this current directory`);
        console.log(`\n ${error} \n`);
    }
}

/**
 * This function returns if a given user is included or excluded from a given Conditional Access policy.
 * It handles:
 *  - Direct user includes/excludes
 *  - Membership in included/excluded groups (including nested groups)
 *  - "All" include
 */
async function calculateIncluded(policy, user, groupList, accessToken, subgroupCache) {
    // Null-safety defaults for policy.conditions.users
    const usersCond = policy?.conditions?.users || {};
    const includeUsers = Array.isArray(usersCond.includeUsers) ? usersCond.includeUsers : [];
    const excludeUsers = Array.isArray(usersCond.excludeUsers) ? usersCond.excludeUsers : [];
    const includeGroups = Array.isArray(usersCond.includeGroups) ? usersCond.includeGroups : [];
    const excludeGroups = Array.isArray(usersCond.excludeGroups) ? usersCond.excludeGroups : [];

    // If no includeUsers/groups and no "All", then policy might not target users -> treat as not included
    // This is a conservative approach; actual CA requires at least one include.
    // 1) Directly excluded user?
    if (excludeUsers.includes(user.id)) return false;

    // 2) Excluded groups (recursive)
    const excludedGroupsRecursive = await calculateSubgroupsRecursive(excludeGroups, accessToken, subgroupCache);
    if (checkArrays(groupList, excludedGroupsRecursive)) return false;

    // 3) All users included?
    if (includeUsers.includes('All')) return true;

    // 4) Directly included
    if (includeUsers.includes(user.id)) return true;

    // 5) Included via group (recursive)
    const includedGroupsRecursive = await calculateSubgroupsRecursive(includeGroups, accessToken, subgroupCache);
    if (checkArrays(groupList, includedGroupsRecursive)) return true;

    return false;
}

/**
 * Returns all subgroups of a given set of groups recursively, including the given group(s) itself.
 * Uses a cross-run cache to avoid duplicate Graph calls.
 */
async function calculateSubgroupsRecursive(groupIds, accessToken, subgroupCache) {
    if (!Array.isArray(groupIds) || groupIds.length === 0) return [];

    const aggregated = new Set();

    for (const groupId of groupIds) {
        if (!groupId) continue;
        const subSet = await fetchSubgroups(groupId, accessToken, subgroupCache);
        for (const g of subSet) aggregated.add(g);
    }

    return Array.from(aggregated);
}

/**
 * Fetch and cache the recursive subgroups of a single group.
 * subgroupCache: Map<groupId, Set<groupId>>
 */
async function fetchSubgroups(groupId, accessToken, subgroupCache) {
    // From cache?
    if (subgroupCache.has(groupId)) {
        return subgroupCache.get(groupId);
    }

    const subgroups = new Set();
    // Always include the current group itself
    subgroups.add(groupId);

    // Fetch transitive members of the group
    let response = [];
    try {
        response = await helper.getAllWithNextLink(accessToken, `/v1.0/groups/${groupId}/transitiveMembers?$select=id`);
    } catch (e) {
        // Most common cause: groupId not found or insufficient permissions
        response = [];
    }

    // Iterate and recurse for members that are groups
    for (const member of (response || [])) {
        // In Graph, groups in transitiveMembers have @odata.type === '#microsoft.graph.group'
        if (member && (member['@odata.type'] === '#microsoft.graph.group' || member['@odata.type'] === 'microsoft.graph.group')) {
            const nested = await fetchSubgroups(member.id, accessToken, subgroupCache);
            for (const g of nested) subgroups.add(g);
        }
    }

    // Cache and return
    subgroupCache.set(groupId, subgroups);
    return subgroups;
}

/**
 * Checks if arr1 and arr2 share at least one element.
 */
function checkArrays(arr1, arr2) {
    if (!Array.isArray(arr1) || !Array.isArray(arr2)) return false;
    const set2 = new Set(arr2);
    for (const v of arr1) {
        if (set2.has(v)) return true;
    }
    return false;
}

/**
 * Wrapper around helper.getAllWithNextLink with error handling.
 */
async function safeGetAll(accessToken, url, label) {
    try {
        const data = await helper.getAllWithNextLink(accessToken, url);
        if (!Array.isArray(data)) {
            console.log(` [${fgColor.FgRed}X${colorReset}] ERROR: could not get ${label}`);
            return undefined;
        }
        return data;
    } catch (e) {
        console.log(` [${fgColor.FgRed}X${colorReset}] ERROR: could not get ${label}`);
        console.log(`\n ${e} \n`);
        return undefined;
    }
}
