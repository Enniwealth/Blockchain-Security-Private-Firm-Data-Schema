//SPDX-License-Identifier: MIT\npragma solidity ^0.8.19;\n\n
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol"
import "@openzeppelin/contracts/security/Pausable.sol";
interface IMYieldToOne is IERC20 {    
function claimYield() external returns (uint256);    
function yieldRecipient() external view returns (address);
}
interface IEarnVault {    function onYield(uint256 amount) external;
}
interface IERC4626 {\n    function totalAssets() external view returns (uint256);\n    
function onYield(uint256 amount) external;\n}\n\n
contract RewardRedistributor is AccessControl, ReentrancyGuard, Pausable {\n    
bytes32 public constant OPERATOR_ROLE = keccak256(\"OPERATOR_ROLE\");\n    \n    
address private USDSC_ADDRESS;\n    
address private treasury;\n    
IEarnVault private earnVault;\n    
IERC4626 private susdscVault;\n    \n    
uint256 private constant RAY = 1e27;\n    
uint256 private constant MAX_FEE_BPS = 10000;\n    
uint256 private feeBps = 500;\n    \n    
uint256 private carryEarn;\n    
uint256 private carryOn;\n    \n    
event Distributed(uint256 indexed blockNumber, uint256 grossYield, uint256 toEarn, uint256 toOn, uint256 toStartale);\n    \n    
constructor(\n        address usdscAddress,\n        address treasuryAddr,\n        IEarnVault earnV,\n        IERC4626 sVault,\n        address admin,\n        address keeper\n    ) {\n        
require(usdscAddress != address(0), \"Zero USDSC address\");\n        
require(treasuryAddr != address(0), \"Zero treasury\");\n        
require(address(earnV) != address(0), \"Zero earnVault\");\n        
require(address(sVault) != address(0), \"Zero sUSDSCVault\");\n        
require(admin != address(0), \"Zero admin\");\n        
require(keeper != address(0), \"Zero keeper\");\n        \n        
USDSC_ADDRESS = usdscAddress;\n        
treasury = treasuryAddr;\n        
earnVault = earnV;\n        
susdscVault = sVault;\n        \n        
_grantRole(DEFAULT_ADMIN_ROLE, admin);\n       
 _grantRole(OPERATOR_ROLE, keeper);\n    
}\n    \n    
function distribute() external whenNotPaused onlyRole(OPERATOR_ROLE) nonReentrant {\n       
 uint256 balanceBefore = IERC20(USDSC_ADDRESS).balanceOf(address(this));\n       
  uint256 minted = IMYieldToOne(USDSC_ADDRESS).claimYield();\n        
  uint256 gross = balanceBefore + minted;\n                
  if (gross == 0) return;             
  uint256 feeToStartale;        
  uint256 toEarn;\n        
  uint256 toOn;\n        
  uint256 toStartaleExtra;\n        
  uint256 sBase;\n        
  uint256 T_earn;\n        
  uint256 T_yield;\n        
  \n        
  (feeToStartale, toEarn, toOn, toStartaleExtra, sBase, T_earn, T_yield) = _calculateSplit(gross, true, false);        
  if (feeToStartale > 0) {\n            
    IERC20(USDSC_ADDRESS).transfer(treasury, feeToStartale);\n        
    }\n        \n        
    if (toEarn > 0) {\n            
    IERC20(USDSC_ADDRESS).approve(address(earnVault), toEarn);\n            
  earnVault.onYield(toEarn);\n        
  }\n        
  \n        
  if (toOn > 0) {\n            
  IERC20(USDSC_ADDRESS).transfer(address(susdscVault), toOn);\n            
  susdscVault.onYield(toOn);\n        
  }\n        
  \n        
  if (toStartaleExtra > 0) {\n            
  IERC20(USDSC_ADDRESS).transfer(treasury, toStartaleExtra);\n        
  }\n        
  \n        
  emit Distributed(block.number, gross, toEarn, toOn, feeToStartale + toStartaleExtra);\n    
  }\n    
  \n    
  function _calculateSplit(\n        
  uint256 gross,\n       
   bool useCarries,\n        
   bool preview\n    
   ) internal returns (uint256 feeToStartale, uint256 toEarn, uint256 toOn, uint256 toStartaleExtra, uint256 sBase, uint256 T_earn, uint256 T_yield) {\n        
   feeToStartale = (gross * feeBps) / MAX_FEE_BPS;\n        
   uint256 net = gross - feeToStartale;\n        
   \n        T_earn = 2000000 * 1e18;\n        
   T_yield = susdscVault.totalAssets();\n        \n        
   uint256 SNow = IERC20(USDSC_ADDRESS).totalSupply();\n        
   sBase = SNow > gross ? SNow - gross : 0;\n        
   \n        
   uint256 S_base = sBase > 0 ? sBase : SNow;\n        
   \n        
   if (useCarries) {\n            
   uint256 numEarn = net * T_earn + carryEarn;\n            
   toEarn = numEarn / S_base;\n            carryEarn = numEarn % S_base;\n            
   \n            
   uint256 numOn = net * T_yield + carryOn;\n            
   toOn = numOn / S_base;\n            
   carryOn = numOn % S_base;\n        
   } else {\n            
    toEarn = (net * T_earn) / S_base;\n            
    toOn = (net * T_yield) / S_base;\n        
    }\n        
    \n        
    toStartaleExtra = net - (toEarn + toOn);\n        
    \n        
    return (feeToStartale, toEarn, toOn, toStartaleExtra, S_base, T_earn, T_yield);\n    
    }\n    
    \n    
    function setTreasury(address _treasury) external onlyRole(DEFAULT_ADMIN_ROLE) {\n        
    require(_treasury != address(0), \"Zero address\");\n        
    treasury = _treasury;\n    
    }\n    
    \n    
    function setFee(uint256 _feeBps) external onlyRole(DEFAULT_ADMIN_ROLE) {\n        
    require(_feeBps <= MAX_FEE_BPS, \"Fee too high\");\n        
    feeBps = _feeBps;   
    }
    }


"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.19;
import \"./Oracle.sol\";\nimport \"@openzeppelin/contracts/token/ERC20/IERC20.sol\";
contract AFIVault {\n    
IERC20 public USDT;\n    
IERC20 public USDe;\n    
Oracle public oracle;\n    \n   
 mapping(address => uint256) public balances;\n    
 uint256 public totalShares;\n    
 uint256 public totalAssets;\n    \n    
 event Deposit(address indexed user, uint256 assets, uint256 shares);\n    
 event Withdraw(address indexed user, uint256 assets, uint256 shares);\n    \n    
 function deposit(uint256 assets) public returns (uint256 shares) {       
 require(assets > 0, \"Zero assets\");\n      
 //VULNERABLE: Uses current oracle rate without protection against same-block manipulation\n        
 uint256 rate = oracle.getRate();\n        
 shares = (assets * 1e18) / rate;\n        \n        
 balances[msg.sender] += assets;\n        
 totalShares += shares;\n        
 totalAssets += assets;\n        \n        
 USDT.transferFrom(msg.sender, address(this), assets);\n        
 emit Deposit(msg.sender, assets, shares);\n        
 return shares;\n    }\n    \n    
 function withdraw(uint256 shares) public returns (uint256 assets) {\n        
 require(shares > 0, \"Zero shares\");\n        
 require(balances[msg.sender] >= shares, \"Insufficient balance\");\n        \n        
 // VULNERABLE: Can withdraw in same block/transaction as deposit if oracle rate changed\n        
 uint256 rate = oracle.getRate();\n        
 assets = (shares * rate) / 1e18;\n        \n        
 balances[msg.sender] -= shares;\n        
 totalShares -= shares;\n        
 totalAssets -= assets;\n        \n        
 USDT.transfer(msg.sender, assets);\n        
 emit Withdraw(msg.sender, assets, shares);\n        
 return assets;\n    }\n    \n    
 function getSharePrice() public view returns (uint256) {\n        
 if (totalShares == 0) return 1e18;\n        
 return (totalAssets * 1e18) / totalShares;  }\n}\n",
