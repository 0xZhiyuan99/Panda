<a name="readme-top"></a>


<!-- GETTING STARTED -->
## Getting Started

This is a research project. We developed a symbolic execution based tool to automatically find smart contract vulnerabilities on the Algorand platform.


### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/Sun-C0ffee/Panda
   ```
2. Change the file mode
   ```sh
   chmod 777 install.sh
   ```
3. Run the script
   ```sh
   ./install.sh
   ```
4. Configure the file `config.ini`
5. Run the tool
   ```sh
   python3 ./panda.py -h
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage
```
usage: panda.py [-h] (-sc | -lsig | -aid ASSET_ID | -tt) [-s SOURCE_FILENAME | -i APP_ID] [-ia] [-ls] [-bp] [-v] [-db]
                [-sl] [-dl BLOCK_SEARCH_DEPTH] [-cl BLOCK_ACCESS_COUNT] [-zt Z3_TIMEOUT] [-gt GLOBAL_TIMEOUT]
                [-rs RULE_SET]

optional arguments:
  -h, --help            show this help message and exit
  -sc, --smart-contract
                        The input file is a smart contract
  -lsig, --logic-signature
                        The input file is a logic signature
  -aid ASSET_ID, --asset-id ASSET_ID
                        The asset ID to be checked
  -tt, --test           Run test scripts
  -s SOURCE_FILENAME, --source SOURCE_FILENAME
                        Filename of the TEAL program
  -i APP_ID, --app-id APP_ID
                        App ID of the smart contract
  -ia, --include-app    Take the signature validator into consideration
  -ls, --load-state     Load the global state of the validator from the blockchain
  -bp, --bypass-validator
                        Bypass the validator if there is no constraint on OnCompletion
  -v, --version         show program's version number and exit
  -db, --debug          Display debug information
  -sl, --silent         Do not display any information
  -dl BLOCK_SEARCH_DEPTH, --depth-limit BLOCK_SEARCH_DEPTH
                        Maximum configuration stack depth for symbolic execution
  -cl BLOCK_ACCESS_COUNT, --count-limit BLOCK_ACCESS_COUNT
                        Maximum block access count for symbolic execution
  -zt Z3_TIMEOUT, --z3-timeout Z3_TIMEOUT
                        Timeout for Z3 (millisecond)
  -gt GLOBAL_TIMEOUT, --global-timeout GLOBAL_TIMEOUT
                        Timeout for symbolic execution (second)
  -rs RULE_SET, --rule-set RULE_SET
                        The detection rule set to be used

```

<p align="right">(<a href="#readme-top">back to top</a>)</p>



## Example Output
The tool will output the vulnerabilities in the smart contract and the corresponding execution backtrace.

[![Screen Shot][product-screenshot]](https://github.com/Sun-C0ffee/Panda)


<p align="right">(<a href="#readme-top">back to top</a>)</p>




<!-- LICENSE -->
## License

Distributed under the GPL-3.0 License. See `LICENSE` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


[product-screenshot]: images/screenshot.png
