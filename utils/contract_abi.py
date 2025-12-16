
# Contract ABI
contract_abi_usdc = [
    {
        "inputs": [
            { "internalType": "address", "name": "account", "type": "address" }
        ],
        "name": "balanceOf",
        "outputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" }
        ], 
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "address", "name": "owner", "type": "address" },
            { "internalType": "address", "name": "spender", "type": "address" }
        ],
        "name": "allowance",
        "outputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "address", "name": "spender", "type": "address" }, 
            { "internalType": "uint256", "name": "amount", "type": "uint256" }
        ],
        "name": "approve",
        "outputs": [
            { "internalType": "bool", "name": "", "type": "bool" }
        ],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "address", "name": "recipient", "type": "address" },
            { "internalType": "uint256", "name": "amount", "type": "uint256" }
        ],
        "name": "transfer",
        "outputs": [
            { "internalType": "bool", "name": "", "type": "bool" }
        ],
        "stateMutability": "nonpayable",
        "type": "function"
    },
]

contract_abi_invite = [
	{
		"inputs": [
			{ "internalType": "address", "name": "_addr", "type": "address" }
		],
		"name": "inviter",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{ "internalType": "address", "name": "", "type": "address" }
		],
		"name": "isgodhoodID",
		"outputs": [
			{ "internalType": "bool", "name": "", "type": "bool" }
		],
		"stateMutability": "view",
		"type": "function"
	},
 	{
		"inputs": [
			{ "internalType": "address", "name": "", "type": "address" }
		],
		"name": "invitereward",
		"outputs": [
			{ "internalType": "uint256", "name": "", "type": "uint256" }
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "claimrewards",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
]

contract_abi_emotion = [
    {
        "inputs": [
            { "internalType": "uint8", "name": "_num", "type": "uint8" }
        ],
        "name": "emotions",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "Issue",
        "outputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" }
        ],
        "name": "IssueInformation",
        "outputs": [
            { "internalType": "uint256", "name": "duration", "type": "uint256" },
            { "internalType": "uint256", "name": "price", "type": "uint256" },
            { "internalType": "uint256", "name": "putmoney", "type": "uint256" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" },
            { "internalType": "address", "name": "", "type": "address" }
        ],
        "name": "IssueAddressEmotions",
        "outputs": [
            { "internalType": "uint8", "name": "", "type": "uint8" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
]

contract_abi_emotion2 = [
    {
        "inputs": [
            { "internalType": "address", "name": "_addr", "type": "address" },
            { "internalType": "uint8", "name": "_num", "type": "uint8" }
        ],
        "name": "emotions",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "Issue",
        "outputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" }
        ],
        "name": "IssueInformation",
        "outputs": [
            { "internalType": "uint256", "name": "duration", "type": "uint256" },
            { "internalType": "uint256", "name": "price", "type": "uint256" },
            { "internalType": "uint256", "name": "putmoney", "type": "uint256" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" },
            { "internalType": "address", "name": "", "type": "address" }
        ],
        "name": "IssueAddressEmotions",
        "outputs": [
            { "internalType": "uint8", "name": "", "type": "uint8" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
]

contract_abi_emotion3 = [
    {
        "inputs": [
            { "internalType": "address", "name": "_addr", "type": "address" }
        ],
        "name": "isBet",
        "outputs": [
            { "internalType": "bool", "name": "", "type": "bool" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getBaseInfo",
        "outputs": [
            { "internalType": "uint256", "name": "period", "type": "uint256" },
            { "internalType": "uint256", "name": "periodBaseUSD", "type": "uint256" },
            { "internalType": "uint256", "name": "periodPrice", "type": "uint256" },
            { "internalType": "uint256", "name": "periodEndStamp", "type": "uint256" },
            { "internalType": "uint256", "name": "periodDuration", "type": "uint256" },
            { "internalType": "uint256", "name": "periodPoolUSD", "type": "uint256" },
            { "internalType": "enum DeepTrain.PeriodStatus", "name": "periodStatus", "type": "uint8" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "address", "name": "_addr", "type": "address" },
            { "internalType": "uint8", "name": "_emotion", "type": "uint8" }
        ],
        "name": "bet",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
]

contract_abi_reward = [
    {
        "inputs": [
            { "internalType": "address", "name": "_addr", "type": "address" }
        ],
        "name": "getReward",
        "outputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "claim",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
]

contract_abi_reward3 = [
    {
        "inputs": [
            { "internalType": "address", "name": "_addr", "type": "address" }
        ],
        "name": "getRewards",
        "outputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "claim",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
]

contract_abi_choice = [
    {
		"inputs": [
			{ "internalType": "address", "name": "_addr", "type": "address" },
			{ "internalType": "uint8", "name": "_option", "type": "uint8" },
			{ "internalType": "uint256", "name": "_soulCount", "type": "uint256" }
		],
		"name": "bet",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{ "internalType": "address", "name": "_addr", "type": "address" }
		],
		"name": "isBet",
		"outputs": [
			{ "internalType": "bool", "name": "", "type": "bool" }
		],
		"stateMutability": "view",
		"type": "function"
	},
    {
        "inputs": [],
        "name": "currentEpoch",
        "outputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "uint256", "name": "_epoch", "type": "uint256" }
        ],
        "name": "getEpochBetResults",
        "outputs": [
            { "internalType": "uint8[3]", "name": "mainstreams", "type": "uint8[3]" },
            { "internalType": "uint8[3]", "name": "eliminateds", "type": "uint8[3]" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
	{
		"inputs": [
			{ "internalType": "uint256", "name": "", "type": "uint256" },
			{ "internalType": "uint256", "name": "", "type": "uint256" },
			{ "internalType": "address", "name": "", "type": "address" }
		],
		"name": "userBets",
		"outputs": [
			{ "internalType": "uint8", "name": "option", "type": "uint8" },
			{ "internalType": "uint256", "name": "soulCount", "type": "uint256" }
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getBaseInfo",
		"outputs": [
			{ "internalType": "uint256", "name": "epoch", "type": "uint256" },
			{ "internalType": "uint256", "name": "epochBaseUSD", "type": "uint256" },
			{ "internalType": "uint256", "name": "epochBaseBox", "type": "uint256" },
			{ "internalType": "uint256", "name": "phase", "type": "uint256" },
			{ "internalType": "uint256", "name": "phaseBaseSoul", "type": "uint256" },
			{ "internalType": "uint256", "name": "phaseBetPrice", "type": "uint256" },
			{ "internalType": "uint256", "name": "phaseEndStamp", "type": "uint256" },
			{ "internalType": "uint256", "name": "phaseDuration", "type": "uint256" },
			{ "internalType": "uint256", "name": "phasePoolUSD", "type": "uint256" },
			{ "internalType": "enum DeepChoice.PhaseStatus", "name": "phaseStatus", "type": "uint8" },
			{ "internalType": "uint256", "name": "simulation", "type": "uint256" }
		],
		"stateMutability": "view",
		"type": "function"
	},
]

contract_abi_award = [
    {
        "inputs": [
            { "internalType": "address", "name": "_addr", "type": "address" }
        ],
        "name": "getRewards",
        "outputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "claim",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
]

contract_abi_mint = [
    {
        "inputs": [
            {"internalType": "address","name": "addr","type": "address"}
        ],
        "name": "getTokenID",
        "outputs": [
            {"internalType": "uint256","name": "","type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "address","name": "addr","type": "address"}
        ],
        "name": "getTokenLevel",
        "outputs": [
            {"internalType": "uint256","name": "","type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "address","name": "addr","type": "address"}
        ],
        "name": "getTokenTicket",
        "outputs": [
            {"internalType": "uint256","name": "","type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256","name": "tokenId","type": "uint256"}
        ],
        "name": "getTokenIDAddr",
        "outputs": [
            {"internalType": "address","name": "","type": "address"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256","name": "tokenId","type": "uint256"}
        ],
        "name": "getTokenIDLevel",
        "outputs": [
            {"internalType": "uint256","name": "","type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256","name": "tokenId","type": "uint256"}
        ],
        "name": "getTokenIDTicket",
        "outputs": [
            {"internalType": "uint256","name": "","type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256","name": "_level","type": "uint256"},
            {"internalType": "uint256","name": "_number","type": "uint256"},
            {"internalType": "bytes","name": "_finalhash","type": "bytes"}
        ],
        "name": "mintNFT",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256","name": "_tokenId","type": "uint256"},
            {"internalType": "uint256","name": "_level","type": "uint256"},
            {"internalType": "uint256","name": "_number","type": "uint256"},
            {"internalType": "bytes","name": "_finalhash","type": "bytes"}
        ],
        "name": "upgradeNFT",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

contract_abi_ticket = [
    {
        "inputs": [
            { "internalType": "uint8", "name": "level", "type": "uint8" },
            { "internalType": "uint8", "name": "rebate", "type": "uint8" },
            { "internalType": "bytes", "name": "_finalhash", "type": "bytes" }
        ],
        "name": "buyTickets",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "uint8", "name": "level", "type": "uint8" },
            { "internalType": "uint256", "name": "quantity", "type": "uint256" },
            { "internalType": "uint8", "name": "rebate", "type": "uint8" },
            { "internalType": "bytes", "name": "_finalhash", "type": "bytes" }
        ],
        "name": "buyTicketsBatch",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "address", "name": "user", "type": "address" }
        ],
        "name": "canPurchaseLevel1",
        "outputs": [
            { "internalType": "bool", "name": "", "type": "bool" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "address", "name": "", "type": "address" }
        ],
        "name": "hasPurchasedLevel1",
        "outputs": [
            { "internalType": "bool", "name": "", "type": "bool" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "uint8", "name": "level", "type": "uint8" }
        ],
        "name": "getTicketLevel",
        "outputs": [
            { 
                "components": [
                    { "internalType": "uint256", "name": "price", "type": "uint256" },
                    { "internalType": "uint256", "name": "baseTickets", "type": "uint256" },
                    { "internalType": "uint256", "name": "bonusTickets", "type": "uint256" },
                    { "internalType": "uint256", "name": "totalTickets", "type": "uint256" }
                ], 
                "internalType": "struct TicketSale.TicketLevel", 
                "name": "", 
                "type": "tuple" 
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "address", "name": "", "type": "address" },
            { "internalType": "uint8", "name": "", "type": "uint8" }
        ],
        "name": "userPurchases",
        "outputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

