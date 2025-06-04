
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