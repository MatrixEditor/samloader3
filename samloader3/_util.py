from xml.etree import ElementTree
from typing import Union


def xml_find(
    doc: ElementTree.Element, path: str, text=False
) -> Union[ElementTree.Element, str]:
    """Utility function to find an XML element and its content in a document.

    This method is used to locate an XML element based on a given path, and return
    either the text or the entire element depending on the 'text' parameter. If
    the element cannot be found, it raises a ValueError exception.

    :param doc: The root ElementTree object containing the XML data.
    :type doc: ElementTree.Element
    :param path: A string specifying the XPath to locate the desired XML element.
    :type path: str
    :param text: If True, return only the content (text) of the found element; otherwise, return the entire element object.
    :type text: bool
    :return: The text or ElementTree object based on 'text' parameter."""
    element = doc.find(path)
    if element is None:
        raise ValueError(f"Could not find XML element at '{path}'!")

    return str(element.text) if text else element
