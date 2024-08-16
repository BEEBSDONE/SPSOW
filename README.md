<h1 align="center" style="font-weight: bold;">SPSOWv4 - Single Port Scanning of The World IPv4</h1>


<p align="center">This is a small script written in C to scan a single port just like an Nmap scan, but it's worldwide. The script creates a list of all the IP addresses possible excluding special-use ones like 192.168.x.x etc...
ATTENTION!!!
If you want to scan all the world, the IP list will be around 50GB when it's done generating, so make sure that you have enough space in your HD.
You can still choose a range of IP instead of all the world. </p>



<h3>Prerequisites</h3>

You can use any C compiler that you want, I used GCC but it's up to you really.

<h2 id="started">🚀 Getting started</h2>

Compile SPSOW.c file by using the command below if you're using GCC:</br>
gcc SPSOW.c -o SPSOW

<h2>Starting</h2>

To start to script, execute the executable created by the compiler like so:</br>
./SPSOW
