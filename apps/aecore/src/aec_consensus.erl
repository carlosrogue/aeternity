%%% -*- erlang-indent-level: 4 -*-
%%%-------------------------------------------------------------------
%%% @copyright (C) 2020, Aeternity Anstalt
%%% @doc Consensus behaviour for customizing node behaviour
%%%      Only one consensus algorithm might be enabled at a given height
%%%      Some consensus algorithms provide a special instrumentation API
%%%      for controlling consensus specific functionality. Some consensus
%%%      modules might overwrite existing functionality in the node using plugins.
%%%      Some consensus modules cannot be disabled after enabling.
%%%      -------------------------------------------------------------
%%%      "Dev Mode" would work in the following way:
%%%      - Disallow disabling of dev mode after it got enabled
%%%      - Optionally use state from a real block
%%%      - Disable sync, gossip, peer discovery etc...
%%%      - Start an in-ram chain simulator or even multiple ones if requested
%%%      - Mock the tx push HTTP endpoint and instantly mine transactions pushed to it
%%%      - Ignore PoW in the block headers
%%%      - Provide an API for instrumenting the chain:
%%%        * Start from <real_block_hash> - starts a chain simulator based on real-world state
%%%          (might be taken from mainnet/testnet).
%%%        * Start empty - starts a new chain simulator
%%%        * Enable/Disable instant tx processing
%%%        * Commit pending txs to a microblock
%%%        * Clone on microblock/fork etc...
%%%        * Set account state etc...
%%%        * N new keyblocks on top of top or given hash
%%%        * Set the given hash as the new top
%%%        * Generate FATE execution traces, change contract code state at will
%%%      -------------------------------------------------------------
%%%      PoA Consensus with one authority would work in the following way:
%%%      - Can be enabled/disabled and switched to another algorithm
%%%      - No plugins are enabled
%%%      - Keyblocks contain the signature of the chosen authority
%%%      - API for querying and changing the authority in the node
%%%     --------------------------------------------------------------
%%%     PoA with a contract
%%%     - Can be enabled/disabled and switched to another algorithm
%%%     - No plugins are enabled
%%%     - Keyblocks contain the signature of the chosen authority taken from a contract
%%%     - The leader is chosen by a contract
%%%     - API for querying the authorities, consensus status
%%% @end
%%% --------------------------------------------------------------------

-module(aec_consensus).

%% API
-export([]).
