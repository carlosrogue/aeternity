-module(aehc_contract_tests).


-include("../../aecontract/src/aect_sophia.hrl").
-include("../../aecontract/include/aecontract.hrl").
-include("../../aecontract/test/include/aect_sophia_vsn.hrl").
-include_lib("aecontract/include/hard_forks.hrl").
-include_lib("eunit/include/eunit.hrl").


-define(cid(__x__), {'@ct', __x__}).
-define(hsh(__x__), {'#', __x__}).
-define(sig(__x__), {'$sg', __x__}).
-define(oid(__x__), {'@ok', __x__}).
-define(qid(__x__), {'@oq', __x__}).

-define(ALOT, (1000000000000000000000000000000000000000000000000000000000000000 * aec_test_utils:min_gas_price())).
-define(CALL_COST, (1000 * aec_test_utils:min_gas_price())).
-define(CALL_GAS, 1000000).

setup() ->
    application:ensure_all_started(gproc),
    aec_test_utils:mock_genesis_and_forks(),
    mock_protocol(),
    ok = lager:start(),
    aec_keys:start_link(),
    {ok, _} = aec_chain_sim:start(),
    ok.

unsetup(ok) ->
    aec_chain_sim:stop(),
    unmock_protocol(),
    aec_test_utils:unmock_genesis_and_forks().


mock_protocol() ->
    meck:new(aec_hard_forks, [passthrough]),
    meck:expect(aec_hard_forks, protocol_effective_at_height, 1,
                fun(_) -> ?IRIS_PROTOCOL_VSN end),
    ok.

unmock_protocol() ->
    meck:unload(aec_hard_forks).

staking_contract_scenarios_test_() ->
    [{foreach, fun setup/0, fun unsetup/1,
      [ {"Unit fun protocol_restrict", fun test_fun_protocol_restrict/0}
      , {"Unit fun valuate", fun test_fun_valuate/0}
      , {"Unit fun staked_tokens", fun test_fun_staked_tokens/0}
      , {"Unit fun requested_withdrawals", fun test_fun_requested_withdrawals/0}
      , {"Unit fun retracted_stake", fun test_fun_retracted_stake/0}
      , {"Unit fun extract_ripe_withdrawals", fun test_fun_extract_ripe_withdrawals/0}
      , {"Unit fun decrease_stake", fun test_fun_decrease_stake/0}
      , {"Unit fun punish", fun test_fun_punish/0}
      , {"Simple deposit/withdraw scenario", fun test_deposit_withdraw/0}
      , {"Complex deposit/withdraw scenario", fun test_complex_deposit_withdraw/0}
      ]}].


make_calldata_from_code(Fun, Args) when is_atom(Fun) ->
    make_calldata_from_code(atom_to_binary(Fun, latin1), Args);
make_calldata_from_code(Fun, Args) when is_binary(Fun) ->
    Args1 = format_fate_args(if is_tuple(Args) -> Args;
                                is_list(Args) -> list_to_tuple(Args);
                                true -> {Args}
                             end),
    FunctionId = make_fate_function_id(Fun),
    aeb_fate_encoding:serialize(aefate_test_utils:encode({FunctionId, Args1})).


make_fate_function_id(FunctionName) when is_binary(FunctionName) ->
    aeb_fate_code:symbol_identifier(FunctionName).

format_fate_args(?cid(B)) ->
    {contract, B};
format_fate_args(?hsh(B)) ->
    {bytes, B};
format_fate_args(?sig(B)) ->
    {bytes, B};
format_fate_args(?oid(B)) ->
    {oracle, B};
format_fate_args(?qid(B)) ->
    {oracle_query, B};
format_fate_args(<<_:256>> = B) ->
    {address, B}; %% Assume it is an address
format_fate_args({bytes, B}) ->
    {bytes, B};
format_fate_args([H|T]) ->
    [format_fate_args(H) | format_fate_args(T)];
format_fate_args(T) when is_tuple(T) ->
    list_to_tuple(format_fate_args(tuple_to_list(T)));
format_fate_args(M) when is_map(M) ->
    maps:from_list(format_fate_args(maps:to_list(M)));
format_fate_args(X) ->
    X.

new_account(Balance) ->
    {ok, #{pubkey := Acct}} = aec_chain_sim:new_account(Balance),
    Acct.

get_balance(Acct) ->
    aec_chain_sim:get_balance(Acct).

restricted_account() ->
    case aec_chain_sim:dict_get(restricted_account, undefined) of
        undefined ->
            Restricted = new_account(?ALOT),
            aec_chain_sim:dict_set(restricted_account, Restricted),
            Restricted;
        Restricted -> Restricted
    end.

staking_contract() ->
    case aec_chain_sim:dict_get(staking_contract, undefined) of
        undefined ->
            error("Staking contract is undefined");
        Con -> Con
    end.

create_staking_contract(#{ deposit_delay := D
                        ,  stake_retraction_delay := R
                        ,  withdraw_delay := W
                        }) ->
    Restricted = restricted_account(),
    {ok, Code} = aeso_compiler:file("apps/aehyperchains/test/contracts/SimpleElection.aes", [{backend, fate}]),
    Serialized = aect_sophia:serialize(Code, ?SOPHIA_CONTRACT_VSN_3),
    CallData = make_calldata_from_code(init, [{D, R, W}]),
    Nonce = aec_chain_sim:next_nonce(Restricted),
    {ok, Tx} = aect_create_tx:new(
                 #{ fee         => ?CALL_COST
                 ,  owner_id    => aeser_id:create(account, Restricted)
                 ,  nonce       => Nonce
                 ,  vm_version  => ?VM_FATE_SOPHIA_2
                 ,  abi_version => ?ABI_FATE_SOPHIA_1
                 ,  deposit     => 2137
                 ,  amount      => 0
                 ,  gas         => ?CALL_GAS
                 ,  gas_price   => aec_test_utils:min_gas_price()
                 ,  ttl         => 0
                 ,  code        => Serialized
                 ,  call_data   => CallData
                 }),
    aec_chain_sim:sign_and_push(Restricted, Tx),
    Contract = aect_contracts:compute_contract_pubkey(Restricted, Nonce),
    aec_chain_sim:dict_set(staking_contract, Contract).


call_staking_contract(Fun, Args, Type) ->
    call_staking_contract(restricted_account(), Fun, Args, Type).
call_staking_contract(Acct, Fun, Args, Type) ->
    call_staking_contract(Acct, 0, Fun, Args, Type).
call_staking_contract(Acct, Value, Fun, Args, Type) ->
    CallData = make_calldata_from_code(Fun, Args),
    Nonce = aec_chain_sim:next_nonce(Acct),
    {ok, Tx} = aect_call_tx:new(
               #{ caller_id   => aeser_id:create(account, Acct)
               ,  nonce       => Nonce
               ,  contract_id => aeser_id:create(contract, staking_contract())
               ,  abi_version => ?ABI_FATE_SOPHIA_1
               ,  fee         => ?CALL_COST
               ,  amount      => Value
               ,  gas         => ?CALL_GAS
               ,  gas_price   => aec_test_utils:min_gas_price()
               ,  call_data   => CallData
               }),
    aec_chain_sim:sign_and_push(Acct, Tx),
    add_microblock(),
    CallId = aect_call:id(Acct, Nonce, staking_contract()),
    {Result, Gas} = get_result(Type, CallId),
    Restricted = restricted_account(),
    {ok, PayBackTx} = aec_spend_tx:new(
        #{ sender_id    => aeser_id:create(account, Restricted)
        ,  recipient_id => aeser_id:create(account, Acct)
        ,  amount       => Gas * aec_test_utils:min_gas_price() + ?CALL_COST
        ,  fee          => ?CALL_COST
        ,  nonce        => aec_chain_sim:next_nonce(Restricted)
        ,  payload      => <<"payback">>
        }),
    aec_chain_sim:sign_and_push(Restricted, PayBackTx),
    add_microblock(),
    Result.

get_result(Type, CallId) ->
    Call = aec_chain_sim:get_call(staking_contract(), CallId),
    Result = case aect_call:return_type(Call) of
                 ok ->
                     Res = aeb_fate_encoding:deserialize(aect_call:return_value(Call)),
                     case aefate_test_utils:decode(Res, Type) of
                        {variant, [0,1], 0, {}} when element(1, Type) =:= option ->
                            none;
                        {variant, [0,1], 1, {Decoded}} when element(1, Type) =:= option ->
                            {some, Decoded};
                        Decoded ->
                            Decoded
                       end;
                 error ->
                     {error, aect_call:return_value(Call)};
                 revert ->
                     Res = aeb_fate_encoding:deserialize(aect_call:return_value(Call)),
                     {revert, aefate_test_utils:decode(Res)}
             end,
    {Result, aect_call:gas_used(Call)}.

random() ->
    4. %% FIXME chosen by a dice toss, perfectly random


%%
%% ENTRYPOINTS
%%

staked_tokens(Acct) ->
    call_staking_contract(restricted_account(), staked_tokens, [Acct], word).

retracted_stake(Acct) ->
    call_staking_contract(restricted_account(), retracted_stake, [Acct], word).

requested_withdrawals(Acct) ->
    call_staking_contract(restricted_account(), requested_withdrawals, [Acct], word).

deposit_stake(Acct, Amount) ->
    call_staking_contract(Acct, Amount, deposit_stake, [], word).

request_withdraw(Acct, Amount) ->
    call_staking_contract(Acct, request_withdraw, [Amount], {tuple, []}).

withdraw(Acct) ->
    call_staking_contract(Acct, withdraw, [], word).

get_computed_leader() ->
    call_staking_contract(get_computed_leader, [], word).

get_leader(Delegates, Rand) ->
    call_staking_contract(get_leader, [Delegates, Rand], word).

punish(BadGuy) ->
    call_staking_contract(punish, [BadGuy], {tuple, []}).


add_microblock() ->
    aec_chain_sim:add_microblock().

add_keyblock() ->
    add_keyblock([restricted_account()]).
add_keyblock(Delegates) ->
    aec_chain_sim:add_keyblock(),
    Leader = get_leader(Delegates, random()),
    aec_chain_sim:add_microblock(),
    Leader.


%%
%% TESTS
%%

-define(assertAbort(X, MSG), ?assertEqual(X, {revert, atom_to_list(MSG)})). % FIXME
-define(assertNegBalance(ACCT, BALANCE), ?assertEqual(?ALOT - BALANCE, get_balance(ACCT))).
-define(assertStakedTokens(ACCT, TOKENS), ?assertEqual(TOKENS, staked_tokens(ACCT))).
-define(assertRequestedWithdrawals(ACCT, TOKENS), ?assertEqual(TOKENS, requested_withdrawals(ACCT))).
-define(assertRetractedStake(ACCT, TOKENS), ?assertEqual(TOKENS, retracted_stake(ACCT))).

-define(INIT_SCENARIO(DD, SRD, WD, ACCS),
        begin
            create_staking_contract(#{ deposit_delay => 1
                                    ,  stake_retraction_delay => 1
                                    ,  withdraw_delay => 2
                                    }),
            add_microblock(),
            add_keyblock([restricted_account()]),

            HackAccs =
                fun Go(ACCS) ->
                        [new_account(?ALOT) || _ <- ACCS];
                    Go(Base) -> Go([{}|Base])
                end,
            ACCS = HackAccs([])
        end).


test_fun_protocol_restrict() ->
    R1 = call_staking_contract(restricted_account(), 0, protocol_restrict, [], {tuple, []}),
    ?assertEqual({}, R1),

    R2 = call_staking_contract(new_account(?ALOT), 0, protocol_restrict, [], {tuple, []}),
    ?assertAbort(R2, 'PROTOCOL_RESTRICTED').

test_fun_valuate() ->
    ?INIT_SCENARIO(0, 0, 0, []),

    %% Just to ensure that aging does not lower the value
    R1 = call_staking_contract(restricted_account(), 0,
                               valuate, [#{value => 100, created => 0}], word),
    R2 = call_staking_contract(restricted_account(), 0,
                               valuate, [#{value => 100, created => 1}], word),
    R3 = call_staking_contract(restricted_account(), 0,
                               valuate, [#{value => 100, created => 100}], word),
    ?assert(R2 < R1),
    ?assert(R3 < R2).

test_fun_staked_tokens() ->
    ?INIT_SCENARIO(0, 0, 0, [Acct1, Acct2, Acct3]),

    deposit_stake(Acct1, 10),
    ?assertStakedTokens(Acct1, 10),
    ?assertStakedTokens(Acct2, 0),
    ?assertStakedTokens(Acct3, 0),
    deposit_stake(Acct2, 100),
    ?assertStakedTokens(Acct1, 10),
    ?assertStakedTokens(Acct2, 100),
    ?assertStakedTokens(Acct3, 0),
    deposit_stake(Acct3, 1000),
    ?assertStakedTokens(Acct1, 10),
    ?assertStakedTokens(Acct2, 100),
    ?assertStakedTokens(Acct3, 1000),
    deposit_stake(Acct3, 20),
    ?assertStakedTokens(Acct1, 10),
    ?assertStakedTokens(Acct2, 100),
    ?assertStakedTokens(Acct3, 1020),
    deposit_stake(Acct2, 200),
    ?assertStakedTokens(Acct1, 10),
    ?assertStakedTokens(Acct2, 300),
    ?assertStakedTokens(Acct3, 1020),
    deposit_stake(Acct1, 2000),
    ?assertStakedTokens(Acct1, 2010),
    ?assertStakedTokens(Acct2, 300),
    ?assertStakedTokens(Acct3, 1020),

    request_withdraw(Acct2, 150),
    withdraw(Acct2),
    ?assertStakedTokens(Acct2, 150).


test_fun_requested_withdrawals() ->
    ?INIT_SCENARIO(0, 0, 0, [Acct1, Acct2]),

    deposit_stake(Acct1, 1000),
    deposit_stake(Acct2, 1000),

    request_withdraw(Acct1, 100),
    ?assertRequestedWithdrawals(Acct1, 100),
    ?assertRequestedWithdrawals(Acct2, 0),
    request_withdraw(Acct2, 10),
    ?assertRequestedWithdrawals(Acct1, 100),
    ?assertRequestedWithdrawals(Acct2, 10),
    request_withdraw(Acct2, 2),
    ?assertRequestedWithdrawals(Acct1, 100),
    ?assertRequestedWithdrawals(Acct2, 12),
    request_withdraw(Acct1, 20),
    ?assertRequestedWithdrawals(Acct1, 120),
    ?assertRequestedWithdrawals(Acct2, 12),
    withdraw(Acct1),
    ?assertRequestedWithdrawals(Acct1, 0),
    ?assertRequestedWithdrawals(Acct2, 12),
    withdraw(Acct2),
    ?assertRequestedWithdrawals(Acct1, 0),
    ?assertRequestedWithdrawals(Acct2, 0).


test_fun_retracted_stake() ->
    ?INIT_SCENARIO(0, 2, 2, [Acct1, Acct2]),

    deposit_stake(Acct1, 1000),
    deposit_stake(Acct2, 100),

    ?assertRetractedStake(Acct1, 0),
    ?assertRetractedStake(Acct2, 0),

    request_withdraw(Acct1, 100),
    request_withdraw(Acct2, 10),

    ?assertRetractedStake(Acct1, 0),
    ?assertRetractedStake(Acct2, 0),

    add_keyblock(),

    request_withdraw(Acct1, 20),
    request_withdraw(Acct2, 2),

    ?assertRetractedStake(Acct1, 0),
    ?assertRetractedStake(Acct2, 0),

    add_keyblock(),

    ?assertRetractedStake(Acct1, 100),
    ?assertRetractedStake(Acct2, 10),

    add_keyblock(),

    ?assertRetractedStake(Acct1, 120),
    ?assertRetractedStake(Acct2, 20).


test_fun_extract_ripe_withdrawals() ->
    ?INIT_SCENARIO(0, 0, 0, []),

    [add_keyblock() || _ <- [1,2,3,4,5,6,7,8,9,0]],
    % Height should be around 10

    Test =
        % Takes: list of HEIGHTS of consequentive withdrawals;
        %        expected list of VALUES of remaining withdrawals;
        % Will assign values accordingly: 1, 2, 3...
        fun(WithdrawalHeights, ExpWithdrawalValues) ->
                ValueSeq = lists:seq(1, lists:length(WithdrawalHeights)),
                Withdrawals = [#{value => V, created => T}
                          || {V, T} <- lists:zip(
                                         ValueSeq,
                                         WithdrawalHeights
                                        )
                         ],
                {T, ResWithdrawals} = call_staking_contract(
                            restricted_account(), 0,
                            extract_ripe_withdrawals, [Withdrawals], word),
                ResValues = lists:sort([V || #{value := V} <- ResWithdrawals]),
                ?assertEqual(lists:sum(ValueSeq) - lists:sum(ResValues), T),
                ?assertEqual(lists:sum(ExpWithdrawalValues), T),

                [ ?assertEqual(L, R)
                 || {L, R} <- lists:zip(lists:sort(ExpWithdrawalValues), ResValues)
                ]
        end,

    % TODO quickcheck?
    Test([0,999], [2]),
    Test([0,0,0,0], [1,2,3,4]),
    Test([0,999,1,998,2,997], 1,3,5),
    Test([999,0,0,0,999,0,0,0,999], [2,3,4,6,7,8]),

    ok.


test_fun_decrease_stake() ->
    S = fun(Value, Created) -> #{value => Value, created => Created} end,
    Test =
        fun(Stakes, Tokens, ExpStakes) ->
                Remaining = call_staking_contract(
                              restricted_account(), 0,
                              decrease_stake, [Stakes, Tokens], word),
                [ ?assertEqual(E, V)
                 || {E, V} <- lists:zip(lists:sort(ExpStakes), lists:sort(Remaining))
                ]
        end,

    % Assuming that aging has not negative effect on the value
    % TODO quickcheck?
    Test(
      [S(1, 2), S(3, 5), S(1, 0)],
      0,
      [S(1, 2), S(3, 5), S(1, 0)]
     ),

    Test(
      [S(10, 0), S(10, 1), S(10, 2), S(10, 3)],
      10,
      [S(10, 1), S(10, 2), S(10, 3)]
     ),

    Test(
      [S(10, 0), S(10, 1), S(10, 2), S(10, 3)],
      15,
      [S(5, 1), S(10, 2), S(10, 3)]
     ),

    Test(
      [S(5, 3), S(10, 2), S(20, 1), S(30, 0)],
      55,
      [S(5, 3), S(5, 2)]
     ),
    ok.


test_fun_punish() ->
    ?INIT_SCENARIO(1, 1, 2, [Acct]),

    deposit_stake(Acct, 10),
    request_withdraw(Acct, 5),
    add_microblock(),

    punish(Acct),
    add_microblock(),

    ?assertStakedTokens(Acct, 0),
    ?assertRequestedWithdrawals(Acct, 0),
    ?assertRetractedStake(Acct, 0).


test_deposit_withdraw() ->
    ?INIT_SCENARIO(1, 1, 2, [Acct]),

    deposit_stake(Acct, 10),
    ?assertStakedTokens(Acct, 10),
    ?assertNegBalance(Acct, 10),

    request_withdraw(Acct, 5),

    add_keyblock(),

    withdraw(Acct),
    ?assertStakedTokens(Acct, 10),
    ?assertRequestedWithdrawals(Acct, 10),
    ?assertRetractedStake(Acct, 0),
    ?assertNegBalance(Acct, 10),

    add_keyblock(),

    withdraw(Acct),
    ?assertStakedTokens(Acct, 5),
    ?assertRequestedWithdrawals(Acct, 0),
    ?assertRetractedStake(Acct, 0),
    ?assertNegBalance(Acct, 5),

    ok.


test_complex_deposit_withdraw() ->
    ?INIT_SCENARIO(2, 2, 4, [A1, A2, A3]),

    deposit_stake(A1, 1000),
    deposit_stake(A2, 500),
    deposit_stake(A1, 1000),
    deposit_stake(A3, 10),
    deposit_stake(A2, 50),
    request_withdraw(A3, 5),

    ?assertStakedTokens(A1, 2000),
    ?assertStakedTokens(A2, 550),
    ?assertStakedTokens(A3, 5),
    ?assertNegBalance(A3, 40),

    add_keyblock(),

    deposit_stake(A1, 1000),
    request_withdraw(A1, 500),
    deposit_stake(A2, 450),
    withdraw(A3),

    ?assertNegBalance(A3, 40),

    ?assertStakedTokens(A1, 2500),
    ?assertStakedTokens(A2, 1000),
    ?assertStakedTokens(A3, 5),

    ?assertRequestedWithdrawals(A1, 500),
    ?assertRequestedWithdrawals(A2, 0),
    ?assertRequestedWithdrawals(A3, 5),

    add_keyblock(),

    withdraw(A1),
    request_withdraw(A2, 1000),
    withdraw(A2),
    withdraw(A3),
    ?assertNegBalance(A1, 3000),
    ?assertNegBalance(A2, 1000),
    ?assertNegBalance(A3, 45),

    request_withdraw(A1, 3000),
    request_withdraw(A3, 45),

    add_keyblock(),
    add_keyblock(),
    add_keyblock(),

    ?assertNegBalance(A1, 0),
    ?assertNegBalance(A2, 0),
    ?assertNegBalance(A3, 0),
    ok.

