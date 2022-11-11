# TRUSTED SETUP Scripts

## Generate cohort tokens

- name: `generate_tokens.py`
    - arguments:
        - `--emails-path`: path to the .csv file containing the list of emails. No header.
        - `--config-path`: path to a json file containing the initial configuration.
    - example run: `poetry run python3 generate_tokens.py --emails-path <...> --config-path <...>`