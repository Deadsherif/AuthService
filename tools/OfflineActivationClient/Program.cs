using OfflineActivationClient;

string outPath = args.Length > 0 ? args[0] : "FirstOption-Device.txt";
string device = DeviceId.Compute();
File.WriteAllText(outPath, device);
string full = Path.GetFullPath(outPath);
Console.WriteLine("First Option — device activation file created:");
Console.WriteLine("  " + full);
Console.WriteLine();
Console.WriteLine("Email this file to First Option to receive your license.");
return 0;
