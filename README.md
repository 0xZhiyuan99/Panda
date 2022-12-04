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
4. Configure the setting file `setting.py`
5. Run the tool
   ```sh
   python3 ./panda.py -h
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

usage: panda.py [-h] (-sc | -lsig | -aid ASSET_ID | -tt) [-s SOURCE_FILENAME | -i APP_ID] [-ia] [-ls] [-v] [-db] [-sl]
                [-dl BLOCK_SEARCH_DEPTH] [-cl BLOCK_ACCESS_COUNT] [-zt Z3_TIMEOUT] [-gt GLOBAL_TIMEOUT]

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


<p align="right">(<a href="#readme-top">back to top</a>)</p>





<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- LICENSE -->
## License

Distributed under the GPL-3.0 License. See `LICENSE` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>
