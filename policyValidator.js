// policyValidator.js - Conditional Access Policy Validation Module

const fgColor = {
    FgRed: "\x1b[31m",
    FgGreen: "\x1b[32m",
    FgYellow: "\x1b[33m",
    FgBlue: "\x1b[34m",
    FgMagenta: "\x1b[35m",
    FgCyan: "\x1b[36m",
    FgGray: "\x1b[90m",
}
const colorReset = "\x1b[0m"

/**
 * Validates CA policies and detects common misconfigurations
 */
class PolicyValidator {
    constructor(policies, users, helper, accessToken) {
        this.policies = policies;
        this.users = users;
        this.helper = helper;
        this.accessToken = accessToken;
        this.issues = [];
    }

    async validate() {
        console.log(` [${fgColor.FgGray}i${colorReset}] Running Policy Validation checks...`);
        
        await this.checkEmptyPolicies();
        await this.checkConflictingPolicies();
        await this.checkBroadExclusions();
        await this.checkBreakGlassAccounts();
        await this.checkPolicyOverlap();
        
        return this.generateReport();
    }

    /**
     * Detect policies with no users in scope
     */
    async checkEmptyPolicies() {
        for (const policy of this.policies) {
            let hasUsers = false;
            
            // Check if includes "All"
            if (policy.conditions.users.includeUsers.includes('All')) {
                hasUsers = true;
            }
            
            // Check if has included users
            if (policy.conditions.users.includeUsers.length > 0 && 
                !policy.conditions.users.includeUsers.includes('All')) {
                hasUsers = true;
            }
            
            // Check if has included groups
            if (policy.conditions.users.includeGroups.length > 0) {
                hasUsers = true;
            }
            
            if (!hasUsers) {
                this.issues.push({
                    severity: 'WARNING',
                    category: 'Empty Policy',
                    policy: policy.displayName,
                    message: 'Policy has no users in scope - consider reviewing or deleting',
                    recommendation: 'Add users/groups to policy or disable it'
                });
            }
        }
    }

    /**
     * Detect conflicting policies (e.g., one blocks, another allows same condition)
     */
    async checkConflictingPolicies() {
        for (let i = 0; i < this.policies.length; i++) {
            for (let j = i + 1; j < this.policies.length; j++) {
                const policy1 = this.policies[i];
                const policy2 = this.policies[j];
                
                // Check for conflicting grant controls
                const hasBlock1 = policy1.grantControls?.builtInControls?.includes('block');
                const hasBlock2 = policy2.grantControls?.builtInControls?.includes('block');
                
                // If one blocks and other doesn't, flag potential conflict
                if (hasBlock1 !== hasBlock2) {
                    // Check if they target similar conditions
                    const sameApps = this.checkArrayOverlap(
                        policy1.conditions.applications.includeApplications,
                        policy2.conditions.applications.includeApplications
                    );
                    
                    if (sameApps) {
                        this.issues.push({
                            severity: 'HIGH',
                            category: 'Conflicting Policies',
                            policy: `${policy1.displayName} <-> ${policy2.displayName}`,
                            message: 'Policies may conflict - one blocks while other allows similar conditions',
                            recommendation: 'Review policy logic and user/app scope'
                        });
                    }
                }
            }
        }
    }

    /**
     * Check for overly broad exclusions (e.g., excluding large groups)
     */
    async checkBroadExclusions() {
        for (const policy of this.policies) {
            const excludedGroups = policy.conditions.users.excludeGroups;
            
            for (const groupId of excludedGroups) {
                try {
                    const members = await this.helper.getAllWithNextLink(
                        this.accessToken, 
                        `/v1.0/groups/${groupId}/members?$count=true`
                    );
                    
                    if (members.length > 100) {
                        this.issues.push({
                            severity: 'MEDIUM',
                            category: 'Broad Exclusion',
                            policy: policy.displayName,
                            message: `Excludes group with ${members.length} members - may be too broad`,
                            recommendation: 'Review if exclusion is necessary for all members'
                        });
                    }
                } catch (error) {
                    // Group might be deleted or inaccessible
                }
            }
            
            // Check for direct user exclusions
            if (policy.conditions.users.excludeUsers.length > 50) {
                this.issues.push({
                    severity: 'MEDIUM',
                    category: 'Broad Exclusion',
                    policy: policy.displayName,
                    message: `Excludes ${policy.conditions.users.excludeUsers.length} users directly`,
                    recommendation: 'Consider using groups instead of individual user exclusions'
                });
            }
        }
    }

    /**
     * Validate break-glass accounts are properly excluded
     */
    async checkBreakGlassAccounts() {
        // Common break-glass account patterns
        const breakGlassPatterns = [
            /break.?glass/i,
            /emergency/i,
            /admin.?backup/i,
            /bg-admin/i
        ];
        
        const breakGlassAccounts = this.users.filter(user => 
            breakGlassPatterns.some(pattern => 
                pattern.test(user.userPrincipalName) || 
                pattern.test(user.displayName)
            )
        );
        
        if (breakGlassAccounts.length === 0) {
            this.issues.push({
                severity: 'HIGH',
                category: 'Break-Glass Accounts',
                policy: 'N/A',
                message: 'No break-glass accounts detected in tenant',
                recommendation: 'Create emergency access accounts and exclude from CA policies'
            });
            return;
        }
        
        // Check each break-glass account
        for (const bgAccount of breakGlassAccounts) {
            const notExcludedFrom = [];
            
            for (const policy of this.policies) {
                const isExcluded = policy.conditions.users.excludeUsers.includes(bgAccount.id);
                
                if (!isExcluded && policy.conditions.users.includeUsers.includes('All')) {
                    notExcludedFrom.push(policy.displayName);
                }
            }
            
            if (notExcludedFrom.length > 0) {
                this.issues.push({
                    severity: 'CRITICAL',
                    category: 'Break-Glass Accounts',
                    policy: notExcludedFrom.join(', '),
                    message: `Break-glass account '${bgAccount.userPrincipalName}' not excluded from ${notExcludedFrom.length} policies`,
                    recommendation: 'Exclude break-glass accounts from all CA policies'
                });
            }
        }
    }

    /**
     * Check for redundant or overlapping policies
     */
    async checkPolicyOverlap() {
        const policyGroups = {};
        
        // Group policies by similar conditions
        for (const policy of this.policies) {
            const key = JSON.stringify({
                apps: policy.conditions.applications.includeApplications.sort(),
                platforms: policy.conditions.platforms?.includePlatforms?.sort() || []
            });
            
            if (!policyGroups[key]) {
                policyGroups[key] = [];
            }
            policyGroups[key].push(policy);
        }
        
        // Find overlapping groups
        for (const [key, policies] of Object.entries(policyGroups)) {
            if (policies.length > 3) {
                this.issues.push({
                    severity: 'INFO',
                    category: 'Policy Overlap',
                    policy: policies.map(p => p.displayName).join(', '),
                    message: `${policies.length} policies target similar apps/platforms`,
                    recommendation: 'Consider consolidating policies to reduce complexity'
                });
            }
        }
    }

    /**
     * Helper to check array overlap
     */
    checkArrayOverlap(arr1, arr2) {
        if (arr1.includes('All') || arr2.includes('All')) return true;
        return arr1.some(item => arr2.includes(item));
    }

    /**
     * Generate validation report
     */
    generateReport() {
        const report = {
            timestamp: new Date().toISOString(),
            totalIssues: this.issues.length,
            critical: this.issues.filter(i => i.severity === 'CRITICAL').length,
            high: this.issues.filter(i => i.severity === 'HIGH').length,
            medium: this.issues.filter(i => i.severity === 'MEDIUM').length,
            low: this.issues.filter(i => i.severity === 'WARNING').length,
            info: this.issues.filter(i => i.severity === 'INFO').length,
            issues: this.issues
        };
        
        // Print summary
        console.log(`\n ${fgColor.FgCyan}=== Policy Validation Summary ===${colorReset}`);
        console.log(` Total Issues Found: ${report.totalIssues}`);
        
        if (report.critical > 0) {
            console.log(` ${fgColor.FgRed}CRITICAL: ${report.critical}${colorReset}`);
        }
        if (report.high > 0) {
            console.log(` ${fgColor.FgRed}HIGH: ${report.high}${colorReset}`);
        }
        if (report.medium > 0) {
            console.log(` ${fgColor.FgYellow}MEDIUM: ${report.medium}${colorReset}`);
        }
        if (report.low > 0) {
            console.log(` ${fgColor.FgGray}WARNING: ${report.low}${colorReset}`);
        }
        if (report.info > 0) {
            console.log(` ${fgColor.FgBlue}INFO: ${report.info}${colorReset}`);
        }
        
        // Print top issues
        console.log(`\n ${fgColor.FgCyan}Top Issues:${colorReset}`);
        const topIssues = this.issues
            .filter(i => ['CRITICAL', 'HIGH'].includes(i.severity))
            .slice(0, 5);
            
        if (topIssues.length === 0) {
            console.log(` ${fgColor.FgGreen}✓${colorReset} No critical or high severity issues found!`);
        } else {
            topIssues.forEach((issue, idx) => {
                console.log(` ${idx + 1}. [${issue.severity}] ${issue.category}: ${issue.message}`);
                console.log(`    Policy: ${issue.policy}`);
                console.log(`    ${fgColor.FgGray}→ ${issue.recommendation}${colorReset}\n`);
            });
        }
        
        return report;
    }
}

module.exports = PolicyValidator;
