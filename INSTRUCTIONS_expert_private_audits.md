# Expert Reviewer Task: Private Audit Platform Collection

## Your Role

As a web3 security expert, you have two responsibilities:

1. **Primary (Today):** Collect high-quality findings from private/premium audit platforms
2. **Secondary (Later):** Review the full dataset for technical accuracy

This document focuses on the collection task.

---

## Why Private Audit Platforms Matter

Public platforms (Code4rena, Sherlock) are being covered by the team. But private auditors often find **higher quality, more sophisticated vulnerabilities**:

- More experienced auditors (often former exploit developers)
- Deeper manual review (not competing with hundreds of others)
- Complex protocol-level bugs that require deep context
- Novel vulnerability classes

This data is gold for our benchmark - especially for testing AI on expert-level findings.

---

## Target Platforms

| Platform | URL | Access | Specialty |
|----------|-----|--------|-----------|
| **Trail of Bits** | github.com/trailofbits/publications | Public reports | Deep technical, novel vulns |
| **Spearbit** | spearbit.com | Some public | High-profile protocols |
| **Cyfrin** | cyfrin.io | Public reports | Educational, well-documented |
| **Pashov Audit Group** | github.com/pashov/audits | Public | Solo expert, detailed findings |
| **Guardian Audits** | guardianaudits.com | Some public | DeFi focused |
| **OpenZeppelin** | blog.openzeppelin.com | Public reports | Industry standard |
| **Consensys Diligence** | consensys.io/diligence | Public reports | Thorough methodology |
| **Dedaub** | dedaub.com | Some public | Static analysis + manual |

---

## Date Requirement

**September 2025 or later** - Same as Gold Standard team.

We need post-cutoff findings that AI models haven't seen in training.

If a platform doesn't have Sept 2025+ reports yet, collect their most recent reports and note the dates - we may use them for a separate analysis.

---

## The Dataset Schema

Use the same schema as the Gold Standard team for consistency:

```json
{
  "id": "gs_[platform]_[project]_[finding]",
  "subset": "gold_standard",
  "language": "solidity or rust or move",
  "chain": "ethereum or solana or sui or other",
  
  "source_platform": "trailofbits or spearbit or cyfrin etc",
  "source_report": "report name",
  "source_finding_id": "finding ID from report",
  "report_url": "link to report or finding",
  "github_repo_url": "link to code repo if available",
  "contest_date": "YYYY-MM-DD",
  
  "severity": "critical or high or medium",
  "vulnerability_type": "from our taxonomy",
  "difficulty_tier": 1 or 2 or 3 or 4,
  "context_level": "single_file or multi_file or cross_contract",
  
  "finding_title": "title from report",
  "finding_description": "full description",
  "attack_scenario": "exploitation steps or impact",
  "fix_description": "recommended mitigation",
  
  "primary_file": {
    "path": "path/to/vulnerable/file",
    "content": "FULL file content",
    "vulnerable_lines": [line, numbers],
    "vulnerable_functions": ["function", "names"]
  },
  
  "context_files": [
    {
      "path": "path/to/related/file",
      "content": "FULL file content",
      "relevance": "why this file matters"
    }
  ],
  
  "call_flow": "A.func() -> B.func() -> vulnerability",
  "context_hint": "expert explanation of the vulnerability",
  
  "is_vulnerable": true,
  
  "expert_notes": "your additional technical analysis (optional)"
}
```

### ID Format by Platform

| Platform | ID Format |
|----------|-----------|
| Trail of Bits | `gs_tob_[project]_[finding]` |
| Spearbit | `gs_spearbit_[project]_[finding]` |
| Cyfrin | `gs_cyfrin_[project]_[finding]` |
| Pashov | `gs_pashov_[project]_[finding]` |
| Guardian | `gs_guardian_[project]_[finding]` |
| OpenZeppelin | `gs_oz_[project]_[finding]` |
| Consensys | `gs_consensys_[project]_[finding]` |
| Dedaub | `gs_dedaub_[project]_[finding]` |

---

## Vulnerability Type Taxonomy

Use these standardized types:

### Universal Types
| Type | Description |
|------|-------------|
| `reentrancy` | External call before state update |
| `access_control` | Missing or improper permission checks |
| `oracle_manipulation` | Price feed manipulation |
| `flash_loan` | Flash loan attack vector |
| `logic_error` | Incorrect business logic |
| `integer_overflow` | Arithmetic overflow/underflow |
| `front_running` | MEV/transaction ordering |
| `dos` | Denial of service |
| `signature_replay` | Signature reuse attack |
| `unchecked_return` | Ignored return values |
| `delegatecall` | Unsafe delegatecall usage |
| `storage_collision` | Proxy storage conflicts |
| `rounding_error` | Precision loss |
| `slippage` | Missing slippage protection |
| `cross_contract` | Inter-contract vulnerability |
| `upgrade_vulnerability` | Proxy upgrade issues |
| `initialization` | Unintialized/reinitializable |

### Advanced Types (You'll likely see these more in private audits)
| Type | Description |
|------|-------------|
| `state_inconsistency` | Inconsistent state across operations |
| `economic_attack` | Protocol economics exploitation |
| `governance_manipulation` | Voting/governance attacks |
| `bridge_vulnerability` | Cross-chain bridge issues |
| `timestamp_dependence` | Unsafe block.timestamp usage |
| `gas_griefing` | Gas-based attacks |
| `phantom_function` | Fallback/receive issues |
| `library_injection` | Malicious library usage |
| `metamorphic` | Metamorphic contract issues |

---

## Difficulty Tier Guidelines

As an expert, you're better positioned to judge difficulty:

| Tier | Description | Characteristics |
|------|-------------|-----------------|
| 1 | **Easy** | Single function, textbook pattern, obvious from reading code |
| 2 | **Medium** | Requires tracing state, multiple functions, standard attack pattern |
| 3 | **Hard** | Cross-contract, requires protocol understanding, complex state |
| 4 | **Expert** | Novel attack, requires deep domain expertise, multi-step exploit chain |

**Private audit findings often skew toward Tier 3-4** since basic bugs are caught by automated tools before manual review.

---

## Platform-Specific Guides

### 1. Trail of Bits

**URL:** https://github.com/trailofbits/publications/tree/master/reviews

**Report Format:** PDF reports in GitHub repo

**Navigation:**
1. Go to the publications repo
2. Browse `reviews/` folder
3. Each folder is a project audit
4. Look for PDFs and any associated code

**Finding Structure:**
- Findings numbered (e.g., TOB-001, TOB-002)
- Severity: Critical, High, Medium, Low, Informational
- Usually includes: Description, Exploit Scenario, Recommendation, Code Reference

**Quality Notes:**
- ToB reports are extremely thorough
- Often find architectural issues, not just code bugs
- May include novel vulnerability classes
- Code references might be to private repos - you may need to reconstruct

**ID Format:** `gs_tob_[project]_TOB001`

---

### 2. Spearbit

**URL:** https://spearbit.com (reports section) or https://github.com/spearbit/portfolio

**Report Format:** PDF reports, some published to GitHub

**Navigation:**
1. Check Spearbit website for public reports
2. Check GitHub portfolio repo
3. Reports often for high-profile protocols (Uniswap, OpenSea, etc.)

**Finding Structure:**
- Detailed technical findings
- Often includes PoC code
- Severity classifications
- May have multiple rounds of review

**Quality Notes:**
- Elite auditor network
- Very sophisticated findings
- Often find business logic issues
- May have Cantina (sister platform) reports too

**ID Format:** `gs_spearbit_[project]_[finding_id]`

---

### 3. Cyfrin

**URL:** https://www.cyfrin.io/audits or https://github.com/Cyfrin/cyfrin-audit-reports

**Report Format:** Public reports, very well-documented

**Navigation:**
1. Go to Cyfrin audits page
2. Reports are organized by project
3. Often include educational context

**Finding Structure:**
- Clear severity ratings
- Detailed explanations (Patrick Collins style - educational)
- Usually includes code snippets
- Recommendations with code examples

**Quality Notes:**
- Very beginner-friendly explanations
- Good for understanding the "why"
- May have video walkthroughs
- Code usually well-referenced

**ID Format:** `gs_cyfrin_[project]_[finding_id]`

---

### 4. Pashov Audit Group

**URL:** https://github.com/pashov/audits

**Report Format:** Markdown files in GitHub

**Navigation:**
1. Browse the audits repo
2. Each folder is a project
3. Reports in markdown format

**Finding Structure:**
- Solo auditor (Pashov) + team findings
- Very detailed technical analysis
- Severity: Critical, High, Medium, Low
- Usually includes exact code references

**Quality Notes:**
- Pashov is extremely experienced
- Finds subtle bugs others miss
- Reports are dense with technical content
- Good for complex DeFi vulnerabilities

**ID Format:** `gs_pashov_[project]_[finding_id]`

---

### 5. Guardian Audits

**URL:** https://guardianaudits.com or their GitHub

**Report Format:** PDF/Markdown reports

**Navigation:**
1. Check website for public portfolio
2. May have GitHub with reports
3. Focus on DeFi protocols

**Finding Structure:**
- Standard severity ratings
- Code references
- Recommendations

**Quality Notes:**
- DeFi specialist
- Good for yield farming, lending protocol bugs
- May find economic attack vectors

**ID Format:** `gs_guardian_[project]_[finding_id]`

---

### 6. OpenZeppelin

**URL:** https://blog.openzeppelin.com/security-audits

**Report Format:** Blog posts and PDFs

**Navigation:**
1. Go to security audits section
2. Major protocols audited
3. Very thorough reports

**Finding Structure:**
- Well-organized by severity
- Includes code references
- Detailed recommendations
- Often multiple audit rounds

**Quality Notes:**
- Industry gold standard
- Thorough methodology
- May include gas optimizations (skip these)
- Focus on critical/high only

**ID Format:** `gs_oz_[project]_[finding_id]`

---

### 7. Consensys Diligence

**URL:** https://consensys.io/diligence/audits/

**Report Format:** Public audit reports

**Navigation:**
1. Browse audit portfolio
2. Filter by recent dates
3. PDF reports available

**Finding Structure:**
- Detailed technical findings
- Clear severity ratings
- Code references with line numbers

**Quality Notes:**
- Very experienced team
- Often audit major protocols
- Thorough documentation

**ID Format:** `gs_consensys_[project]_[finding_id]`

---

### 8. Dedaub

**URL:** https://dedaub.com/security-audits

**Report Format:** Public reports

**Navigation:**
1. Check security audits section
2. May have GitHub repo as well

**Finding Structure:**
- Combined static analysis + manual findings
- May reference their analysis tools
- Clear severity ratings

**Quality Notes:**
- Strong on complex decompilation
- Good for optimized/low-level code bugs
- May find bytecode-level issues

**ID Format:** `gs_dedaub_[project]_[finding_id]`

---

## Code Acquisition Strategies

Private audits often don't link to public repos. Strategies:

### 1. Check if Protocol is Open Source
- Search GitHub for the protocol name
- Check if audit references a specific commit
- Look for the vulnerable version (pre-fix)

### 2. Use Etherscan/Block Explorers
- If contract is deployed, get verified source
- Note: This is the deployed version, might be post-fix
- Check contract creation date vs audit date

### 3. Reconstruct from Report
- If report shows code snippets, expand them
- Use your expertise to fill in context
- Mark `"code_source": "reconstructed"`

### 4. Check Wayback Machine
- Some repos go private after audit
- Archive.org might have the old version

### 5. Contact Protocol (Last Resort)
- Some protocols will share code if you explain research purpose
- Only if truly needed

---

## Example Entry: Trail of Bits Finding

**From a ToB report:**

```
Finding TOB-PROTO-003: Reentrancy in Withdrawal Queue Processing

Severity: High

Description:
The processQueue() function in WithdrawalManager.sol iterates through pending 
withdrawals and sends ETH to users. The external call is made before updating 
the withdrawal status, allowing a malicious contract to re-enter and process 
the same withdrawal multiple times.

Location: contracts/WithdrawalManager.sol#L145-L167

function processQueue(uint256 count) external onlyKeeper {
    for (uint256 i = 0; i < count; i++) {
        Withdrawal storage w = queue[i];
        if (w.status != Status.Pending) continue;
        
        // External call before state update
        (bool success,) = w.recipient.call{value: w.amount}("");
        require(success, "Transfer failed");
        
        w.status = Status.Processed;  // Updated after call
    }
}

Recommendation:
Update withdrawal status before making the external call. Consider using
ReentrancyGuard or the checks-effects-interactions pattern.
```

**Your dataset entry:**

```json
{
  "id": "gs_tob_protocolx_TOB003",
  "subset": "gold_standard",
  "language": "solidity",
  "chain": "ethereum",
  
  "source_platform": "trailofbits",
  "source_report": "2025-10-protocolx",
  "source_finding_id": "TOB-PROTO-003",
  "report_url": "https://github.com/trailofbits/publications/blob/master/reviews/ProtocolX.pdf",
  "github_repo_url": "https://github.com/protocolx/contracts",
  "contest_date": "2025-10-20",
  
  "severity": "high",
  "vulnerability_type": "reentrancy",
  "difficulty_tier": 2,
  "context_level": "single_file",
  
  "finding_title": "Reentrancy in Withdrawal Queue Processing",
  "finding_description": "The processQueue() function in WithdrawalManager.sol iterates through pending withdrawals and sends ETH to users. The external call is made before updating the withdrawal status, allowing a malicious contract to re-enter and process the same withdrawal multiple times.",
  "attack_scenario": "1. Attacker creates withdrawal request\n2. Keeper calls processQueue()\n3. ETH sent to attacker's contract\n4. Attacker's receive() calls processQueue() or another entry point\n5. Original withdrawal still marked Pending\n6. Withdrawal processed again\n7. Repeat until queue drained",
  "fix_description": "Update withdrawal status before making the external call. Consider using ReentrancyGuard or the checks-effects-interactions pattern:\n\nw.status = Status.Processed;  // Update BEFORE call\n(bool success,) = w.recipient.call{value: w.amount}(\"\");\nrequire(success);",
  
  "primary_file": {
    "path": "contracts/WithdrawalManager.sol",
    "content": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.19;\n\nimport \"@openzeppelin/contracts/access/Ownable.sol\";\n\ncontract WithdrawalManager is Ownable {\n    enum Status { None, Pending, Processed, Cancelled }\n    \n    struct Withdrawal {\n        address recipient;\n        uint256 amount;\n        Status status;\n        uint256 timestamp;\n    }\n    \n    Withdrawal[] public queue;\n    mapping(address => uint256) public pendingAmounts;\n    \n    address public keeper;\n    \n    modifier onlyKeeper() {\n        require(msg.sender == keeper, \"Not keeper\");\n        _;\n    }\n    \n    constructor(address _keeper) {\n        keeper = _keeper;\n    }\n    \n    function requestWithdrawal(uint256 amount) external {\n        require(amount > 0, \"Zero amount\");\n        require(pendingAmounts[msg.sender] == 0, \"Existing request\");\n        \n        queue.push(Withdrawal({\n            recipient: msg.sender,\n            amount: amount,\n            status: Status.Pending,\n            timestamp: block.timestamp\n        }));\n        \n        pendingAmounts[msg.sender] = amount;\n    }\n    \n    function processQueue(uint256 count) external onlyKeeper {\n        uint256 len = queue.length < count ? queue.length : count;\n        \n        for (uint256 i = 0; i < len; i++) {\n            Withdrawal storage w = queue[i];\n            if (w.status != Status.Pending) continue;\n            \n            // VULNERABILITY: External call before state update\n            (bool success,) = w.recipient.call{value: w.amount}(\"\");\n            require(success, \"Transfer failed\");\n            \n            // State update happens AFTER external call\n            w.status = Status.Processed;\n            pendingAmounts[w.recipient] = 0;\n        }\n    }\n    \n    function getQueueLength() external view returns (uint256) {\n        return queue.length;\n    }\n    \n    receive() external payable {}\n}",
    "vulnerable_lines": [145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159],
    "vulnerable_functions": ["processQueue"]
  },
  
  "context_files": [],
  
  "call_flow": "Keeper.processQueue() -> WithdrawalManager loops -> .call{value}() to attacker -> Attacker.receive() -> re-enters before status update",
  "context_hint": "Classic reentrancy in a queue processing context. The withdrawal status is only updated after the ETH transfer, allowing the same withdrawal to be processed multiple times in a single transaction through recursive calls.",
  
  "is_vulnerable": true,
  
  "expert_notes": "This is a variant of reentrancy specific to batch processing patterns. The loop structure makes it more subtle than single-withdrawal reentrancy. A nonReentrant modifier on processQueue would fix this."
}
```

---

## Example Entry: Spearbit Complex Finding

**From a Spearbit report:**

```
Finding: Sandwich Attack Vector in AMM Integration

Severity: High

The protocol integrates with an external AMM for token swaps during liquidations.
The liquidation function does not specify a minimum output amount or use a 
deadline, making it vulnerable to sandwich attacks.

Additionally, the AMM price can be manipulated in the same block, allowing an
attacker to:
1. Manipulate AMM price
2. Trigger liquidation at manipulated price
3. Profit from the arbitrage

This is a cross-contract issue involving:
- LiquidationEngine.sol (calls swap)
- AMM adapter (no slippage protection)
- External AMM pool (manipulable)
```

**Your dataset entry:**

```json
{
  "id": "gs_spearbit_defiprotocol_005",
  "subset": "gold_standard",
  "language": "solidity",
  "chain": "ethereum",
  
  "source_platform": "spearbit",
  "source_report": "2025-10-defiprotocol",
  "source_finding_id": "SPEARBIT-005",
  "report_url": "https://github.com/spearbit/portfolio/blob/master/pdfs/DefiProtocol.pdf",
  "github_repo_url": "https://github.com/defiprotocol/v2-core",
  "contest_date": "2025-10-25",
  
  "severity": "high",
  "vulnerability_type": "slippage",
  "difficulty_tier": 3,
  "context_level": "cross_contract",
  
  "finding_title": "Sandwich Attack Vector in AMM Integration",
  "finding_description": "The protocol integrates with an external AMM for token swaps during liquidations. The liquidation function does not specify a minimum output amount or use a deadline, making it vulnerable to sandwich attacks. Additionally, the AMM price can be manipulated in the same block, allowing attackers to profit from liquidation events.",
  "attack_scenario": "1. Monitor mempool for liquidation transactions\n2. Front-run: Manipulate AMM price by swapping large amount\n3. Victim's liquidation executes at manipulated (bad) price\n4. Back-run: Reverse the manipulation to restore price\n5. Attacker profits from the spread, protocol/user loses value",
  "fix_description": "1. Add minAmountOut parameter to liquidation swap\n2. Add deadline parameter to prevent stale transactions\n3. Consider using TWAP oracle for liquidation pricing\n4. Add slippage tolerance configuration",
  
  "primary_file": {
    "path": "contracts/LiquidationEngine.sol",
    "content": "<FULL FILE CONTENT>",
    "vulnerable_lines": [234, 235, 236, 237, 238, 239, 240],
    "vulnerable_functions": ["liquidate", "_executeSwap"]
  },
  
  "context_files": [
    {
      "path": "contracts/adapters/UniswapAdapter.sol",
      "content": "<FULL FILE CONTENT>",
      "relevance": "Adapter that interfaces with AMM - passes 0 for minAmountOut, no deadline"
    },
    {
      "path": "contracts/interfaces/ILiquidationEngine.sol",
      "content": "<FULL FILE CONTENT>",
      "relevance": "Interface showing liquidation function signature lacks slippage params"
    }
  ],
  
  "call_flow": "Attacker.frontrun() -> AMM.swap() [manipulate price] -> Keeper.liquidate() -> LiquidationEngine.liquidate() -> UniswapAdapter.swap() [no slippage protection] -> AMM.swap() [bad rate] -> Attacker.backrun() -> AMM.swap() [restore price]",
  "context_hint": "Cross-contract MEV vulnerability. The liquidation flow goes through an adapter to an external AMM without any slippage protection. Because liquidations are predictable (health factor drops below threshold), attackers can sandwich them profitably. The vulnerability exists in the integration layer, not in any single contract.",
  
  "is_vulnerable": true,
  
  "expert_notes": "This is increasingly common in DeFi integrations. The protocol might argue the keeper should set appropriate gas, but that's not sufficient protection. Need explicit minAmountOut based on oracle price with acceptable deviation. Also consider private mempool solutions for liquidations."
}
```

---

## Severity Mapping

Different firms use different severity scales. Map them to ours:

| Firm's Rating | Our Rating |
|---------------|------------|
| Critical | `"critical"` |
| High | `"high"` |
| Medium | `"medium"` |
| Low | Skip (don't include) |
| Informational | Skip |
| Gas Optimization | Skip |

**We only want Critical, High, and Medium severity findings.**

---

## Quality Indicators for Private Audits

Since you're an expert, you can judge quality. Prioritize findings that:

✅ **High Priority:**
- Novel vulnerability classes
- Complex attack chains
- Cross-contract interactions
- Business logic flaws
- Economic/game-theoretic attacks
- Protocol-specific vulnerabilities

⚠️ **Medium Priority:**
- Standard patterns in new context
- Well-documented with clear PoC
- Interesting edge cases

❌ **Low Priority (Consider Skipping):**
- Basic well-known patterns (simple reentrancy, basic overflow)
- Findings without enough detail to reproduce
- Centralization risks (subjective)
- Theoretical without practical exploit path

---

## Expert Notes Field

Unlike the other team members, you can add an `expert_notes` field with your professional analysis:

```json
"expert_notes": "This vulnerability is similar to the Euler donation attack but exploits a different mechanism. The protocol's share accounting doesn't handle direct token transfers, creating an inflation vector. Interesting that ToB caught this - it requires understanding both ERC4626 mechanics and the protocol's custom modifications."
```

Use this for:
- Connections to other known vulnerabilities
- Why this is particularly interesting/novel
- Additional context from your expertise
- Recommendations for our research

---

## Process

### Phase 1: Survey Platforms (Hour 1-2)
1. Visit each platform
2. Check what reports are available from Sept 2025+
3. Note which platforms have the best coverage
4. Prioritize based on availability

### Phase 2: Deep Collection (Hour 3-10)
1. Work through platforms in order of richest content
2. Extract High/Critical findings first
3. Then Medium severity
4. Get full code where possible

### Phase 3: Quality Pass (Hour 10-12)
1. Review your entries for completeness
2. Verify code is full files not snippets
3. Check severity and difficulty ratings
4. Add expert notes where valuable

---

## Target Output

**Realistic targets given platform availability:**
- 20-40 high-quality findings from private auditors
- Focus on Tier 3-4 difficulty (the interesting stuff)
- Full code context for each

**Quality over quantity** - 20 excellent expert-level findings are worth more than 50 basic ones.

---

## Coordination

### Your Work Complements the Team
- Arvind: Code4rena
- Laura: Sherlock  
- Courage: Solodit + QA
- Guanyu: Temporal Probe (Rekt.news)
- **You: Private auditors**

### Later: Dataset Review
After collection, you'll review entries from all team members for:
- Technical accuracy of vulnerability classification
- Correct difficulty tier assignment
- Code completeness
- Missing context files
- Description quality

We'll create a separate review protocol for that phase.

---

## Quick Reference

### Your Platforms
- 🔗 Trail of Bits: github.com/trailofbits/publications
- 🔗 Spearbit: spearbit.com + github.com/spearbit/portfolio
- 🔗 Cyfrin: cyfrin.io/audits
- 🔗 Pashov: github.com/pashov/audits
- 🔗 Guardian: guardianaudits.com
- 🔗 OpenZeppelin: blog.openzeppelin.com/security-audits
- 🔗 Consensys: consensys.io/diligence/audits
- 🔗 Dedaub: dedaub.com

### Date Requirement
September 2025 or later preferred. Note dates for all entries.

### Subset Value
`"gold_standard"` (same as rest of team)

### Your Edge
You understand these bugs deeply - use that to:
- Correctly classify difficulty
- Write accurate context hints
- Identify cross-contract dependencies
- Add valuable expert notes

---

## Questions?

Message Paul if:
- Platform access issues
- Unclear how to handle a specific report format
- Found something really novel worth discussing
- Need to coordinate with other team members

Your expertise is critical for dataset quality. Thanks for joining! 🚀
