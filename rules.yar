rule MalwareExample
{
    strings:
        $b = "E2 34 A1 C8 23 FB"
        $c = "i am a virus."
    
    condition:
        any of them
}
