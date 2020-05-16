# rbcrypt

bcrypt binding for Erlang, without `erl_interface`.

## install

On `rebar.config`, add

```erlang
{deps, [
    {rbcrypt, {git, "https://github.com/yjh0502/rbcrypt", {branch, "master"}}}
]}.
```

## usage

```erlang
Pw = <<"some_password">>,
Cost = 12,
{ok, Hash} = rbcrypt:hash(Pw, Cost),
{ok, true} = rbcrypt:verify(Pw, Hash),
ok.
```
