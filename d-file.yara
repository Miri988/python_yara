import "pe"

rule D_file
{
    meta:
    description = "Rules for D_file"
    author = "Irena"
    date ="04/01/2024"
    version = "1.1.0"

    strings:
    $d1 = { 50 4B 03 04 }
    $d2 = { 50 4b 01 02 } //center dir
    $d3 = { 50 4b 05 06 } //end center dir

    condition:
    $d1
    and $d2
    and $d3
}

rule rpm
{
    strings:
    $rpm = { ed ab ee db }   
    
    condition:
    $rpm
}

rule bin
{
    strings:
    $bin = { 53 50 30 31 }
    
    condition:
    $bin
}

rule gif
{
    strings:
    $gif = { 47 49 46 38 37 61 }
    
    condition:
    $gif
}

rule tif
{
    strings:
    $tif = { 49 49 2A 00 }
    
    condition:
    $tif
}

rule jpg
{
    strings:
    $jpg = { FF D8 FF DB }
    
    condition:
    $jpg
}

rule zip
{
    strings:
    $zip = { 50 4B 03 04 }

    condition:
    $zip
}

rule rar
{
    strings:
    $rar = { 52 61 72 21 1A 07 01 00 }
    
    condition:
    $rar
}

rule png
{
    strings:
    $png = { 89 50 4E 47 0D 0A 1A 0A }
    
    condition:
    $png
}

rule pdf
{
    strings:
    $pdf = { 25 50 44 46 2D }
    
    condition:
    $pdf
}

rule mp3
{
    strings:
    $mp3 = { 49 44 33 }
        
    condition:
    $mp3
}

rule doc
{
    strings:
    $doc = { D0 CF 11 E0 A1 B1 1A E1 }
    
    condition:
    $doc
}

rule rtf
{
    strings:
    $rtf = { 7B 5C 72 74 66 31 }

    condition:
    $rtf
}

rule exe
{
    strings:
    $exe = { 4D 5A }
    
    condition:
    $exe
}