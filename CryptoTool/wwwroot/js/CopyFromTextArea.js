function CopyToClipboard(elementId) {

    var copyText = document.getElementById(elementId);

    copyText.select();


    navigator.clipboard.writeText(copyText.value);

        document.getSelection().removeAllRanges();
    copyText.blur();

    alert("Copied to clipboard!");

    
}