-module(aehc_contract_tests).


-include("../../aecontract/src/aect_sophia.hrl").
-include("../../aecontract/include/aecontract.hrl").
-include("../../aecontract/test/include/aect_sophia_vsn.hrl").
-include_lib("eunit/include/eunit.hrl").


-define(cid(__x__), {'@ct', __x__}).
-define(hsh(__x__), {'#', __x__}).
-define(sig(__x__), {'$sg', __x__}).
-define(oid(__x__), {'@ok', __x__}).
-define(qid(__x__), {'@oq', __x__}).

-define(ALOT, 1000000000000000000000000000000000000000000000000000000000000000).
-define(CALL_COST, 100000000000000).
-define(TOKENS(X), X * 1000000 * ?CALL_COST).
%%-define(let(X, V, Body), (fun(X) -> Body end)(V)).
-define(assertBalanceEqual(B1, B2), ?assert(abs((B1) - (B2)) < ?TOKENS(1)/2)).
%%-define
%%    (assertTokenDelta(Acct, Cost, Action),
%%    (fun(Before) aec_chain_sim:get_balance(Acct), begin
%%        Action,
%%            ?assertBalanceEqual(Before, aec_chain_sim:get_balance(Acct))
%%        end)
%%    ).


setup() ->
    application:ensure_all_started(gproc),
    aec_test_utils:mock_genesis_and_forks(),
    ok = lager:start(),
    aec_keys:start_link(),
    {ok, _} = aec_chain_sim:start(),
    ok.

unsetup(ok) ->
    aec_chain_sim:stop(),
    aec_test_utils:unmock_genesis_and_forks().

staking_contract_scenarios_test_() ->
    [{foreach, fun setup/0, fun unsetup/1,
      [ {"Simple deposit/withdraw scenario", fun deposit_test/0}
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
                 ,  vm_version  => ?VM_FATE_SOPHIA_1
                 ,  abi_version => ?ABI_FATE_SOPHIA_1
                 ,  deposit     => 2137
                 ,  amount      => 0
                 ,  gas         => ?CALL_COST
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
               ,  gas         => ?CALL_COST
               ,  gas_price   => aec_test_utils:min_gas_price()
               ,  call_data   => CallData
               }),
    aec_chain_sim:sign_and_push(Acct, Tx),
    add_microblock(),
    CallId = aect_call:id(Acct, Nonce, staking_contract()),
    {Result, Gas} = get_result(Type, CallId),
    Restricted = restricted_account(),
    PayBackTx = aec_spend_tx:new(
        #{ sender_id    => Restricted
        ,  recipient_id => Acct
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
                     case aere_response:decode(Res, Type) of
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
                     {revert, aere_response:decode(Res)}
             end,
    {Result, aect_call:gas_used(Call)}.

random() ->
    4. %% FIXME chosen by a dice toss, perfectly random

staked_tokens(Acct) ->
    call_staking_contract(Acct, staked_tokens, [Acct], word).

retracted_stake(Acct) ->
    call_staking_contract(Acct, retracted_stake, [Acct], word).

requested_withdrawals(Acct) ->
    call_staking_contract(Acct, requested_withdrawals, [Acct], word).

deposit_stake(Acct, Amount) ->
    call_staking_contract(Acct, Amount, deposit_stake, [], word).

request_withdraw(Acct, Amount) ->
    call_staking_contract(Acct, request_withdraw, [Amount], {tuple, []}).

withdraw(Acct) ->
    call_staking_contract(Acct, withdraw, [], word).

get_computed_leader() ->
    call_staking_contract(get_computed_leader, [], address).

get_leader(Delegates, Rand) ->
    call_staking_contract(get_leader, [Delegates, Rand], address). %% FIXME

punish(BadGuy) ->
    call_staking_contract(punish, [BadGuy], {tuple, []}).


add_microblock() ->
    aec_chain_sim:add_microblock().

add_keyblock(Delegates) ->
    aec_chain_sim:add_keyblock(),
    Leader = get_leader(Delegates, random()),
    aec_chain_sim:add_microblock(),
    Leader.


deposit_test() ->
    create_staking_contract(#{ deposit_delay => 1
                            ,  stake_retraction_delay => 1
                            ,  withdraw_delay => 2
                            }),
    add_microblock(),
    add_keyblock([]),

    Acct = new_account(?TOKENS(100)),
    deposit_stake(Acct, ?TOKENS(10)),
    add_microblock(),
    ?assertEqual(?TOKENS(10), staked_tokens(Acct)),
    ?assertBalanceEqual(get_balance(Acct), ?TOKENS(90)),

    request_withdraw(Acct, ?TOKENS(5)),
    add_microblock(),

    add_keyblock([]),


    withdraw(Acct),
    ?assertEqual(?TOKENS(10), staked_tokens(Acct)),
    ?assertEqual(?TOKENS(10), requested_withdrawals(Acct)),
    ?assertEqual(?TOKENS(0), retracted_stake(Acct)),
    ?assertBalanceEqual(get_balance(Acct), ?TOKENS(90)),

    add_keyblock([]),

    withdraw(Acct),
    ?assertEqual(?TOKENS(5), staked_tokens(Acct)),
    ?assertEqual(?TOKENS(0), requested_withdrawals(Acct)),
    ?assertEqual(?TOKENS(0), retracted_stake(Acct)),
    ?assertBalanceEqual(get_balance(Acct), ?TOKENS(95)),

    ok.
