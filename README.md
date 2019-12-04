# llrp2hrp
A service that talks Low Level Reader Protocol (LLRP) on the frontend and
 Hopeland Reader Protocol (HRP) on the backend

The script implements an LLRP server and addresses the necessary startup and
configuration steps to start sending ROAccessReports that contain EPC data
retrieved from the HRP reader.

This project was primarily designed to feed Webscorer with data from a Hopeland
 CL7026C4 reader so that it could be used for timing trail running races.


Dependencies:
* sllurp
* hrp
