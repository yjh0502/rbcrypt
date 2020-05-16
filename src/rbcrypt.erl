-module(rbcrypt).
-compile([no_native]).

-on_load(init/0).
-export([hash/1, hash/2, verify/2]).

-define(DEFAULT_COST, 12).

hash(Data) ->
    nif_hash(Data, ?DEFAULT_COST).

hash(Data, Cost) ->
    nif_hash(Data, Cost).

verify(Password, Hash) ->
    nif_verify(Password, Hash).

init() ->
    PrivDir = code:priv_dir(?MODULE),
    erlang:load_nif(filename:join(PrivDir, "crates/rbcrypt/librbcrypt"), 0).

-define(NOT_LOADED, not_loaded(?LINE)).

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).

nif_hash(_Data, _Cost) ->
    ?NOT_LOADED.

nif_verify(_Password, _Hash) ->
    ?NOT_LOADED.
