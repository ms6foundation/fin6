"""The command line: one tool that drives all three packages.

    fin6 genesis new  testnet/ --nodes 7
    fin6 net up       testnet/
    fin6 wallet send  testnet/ --name treasury --to <address> --amount 250
    fin6 light verify testnet/ --name bob

It lives outside `chain`, `client` and `wallet` because it uses all of them and
none of them should have to know it exists.
"""
