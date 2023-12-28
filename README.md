# samloader3

Cross plattform Firmware downloader and decryptor for Samsung devices with maximum download speed.
A list of API examples are given in the documentation available at [Github-Pages](https://matrixeditor.github.io/samloader3).

> [!NOTE]
> This project was formerly hosted at `nlscc/samloader`, and has moved from `samloader/samloader` to a refactored and updated version with enhanced CLI support and an API documentation.

## Installation

You can easily install it by using the `pip` package manager.

```console
pip install git+https://github.com/MatrixEditor/samloader3.git
```

## CLI

The interface procided here is separated into two layers. In The first one, one can set basic options, such as the device's country code, model name, IMEI number or a global timeout value. Next, you will
operate on a shell that takes commands with arguments as input.

```console
$ python3 -m samloader3 -M "SM-A336B" -R "SFR" -I "12345678901234"
(sl3)> # type commands here
```

### List firmware information

Utilizing the `list` command you can list all available firmwares for a specific model within
the selected region.

> [!NOTE]
> Make sure to always set the device's model name and region code, otherwise you won't get any
> valid results. For simplicity, we don't write the model and region code explicitly.

Using this command without any arguments will result in a table view that displays all available
versions:

<p align="center">

![cmd_list](/docs/source/cmd_list.png)

</p>

> [!TIP]
> If you just want to list the latest firmware use `-l` and if you want to print out the version
> strings only, use `-q`. Using `-v VERSION` you can also view details on one specific version.


### Download Firmware

With this updated version of `samloader`, you can download multiple firmware files at one (though, most likely not a real use case) and accelerate to the maximum download speed. Using one version
string from the output before, simply run the following command:

```console
(sl3)> download -o "/path/to/destination/" "$version1" "$version2" ...
```

As these files can be huge, once canceled, the donwload will resume at the current download
position. You can disable that behaviour using `--no-cache`. With a special version identifier (`*`) you can download all firmware binaries at once.

> [!WARNING]
> Because of some issues with python.rich, parallel download is disabled by default. It can be
> enabled using `--parallel`.

To decrypt files directly after downloading them, use `--decrypt`.


### Decrypt Firmware

The decryption command (`decrypt`) is designd to operate on one file only. You just have
to provide a version number and the file path:

```console
(sl3)> decrypt -v "$version" "/path/to/firmware.zip.enc4"
```

> [!TIP]
> If you only want to generate the decryption key, use `--key-only`. Note that the actual
> key is the MD5 value

## License

Distributed under the GNU General Public License (V3). See LICENSE for more information.