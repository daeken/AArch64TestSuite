using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using UltimateOrb;
using UnicornSharp;

namespace UnicornEvaluator {
	unsafe class Program {
		static byte[][] baselineStates;
		
		static void Main(string[] args) {
			var fp = File.OpenRead("../baselineStates.bin");
			baselineStates = new byte[fp.ReadByte()][];
			for(var i = 0; i < baselineStates.Length; ++i) {
				baselineStates[i] = new byte[16 * 32 + 8 * 31 + 1];
				fp.Read(baselineStates[i], 0, 16 * 32 + 8 * 31 + 1);
			}
			
			if(args.Length == 0)
				StartServer();
			else
				StartClient(int.Parse(args[0]));
		}

		static void SendAll(Socket socket, byte[] buffer, int length = -1) {
			var offset = 0;
			var remainder = length == -1 ? buffer.Length : length;
			while(remainder > 0) {
				var sent = socket.Send(buffer, offset, remainder, SocketFlags.None);
				offset += sent;
				remainder -= sent;
			}
		}

		static void RecvAll(Socket socket, byte[] buffer) {
			var offset = 0;
			var remainder = buffer.Length;
			while(remainder > 0) {
				var got = socket.Receive(buffer, offset, remainder, SocketFlags.None);
				offset += got;
				remainder -= got;
			}
		}

		static void StartServer() {
			var allInsns =
				JsonConvert.DeserializeObject<Dictionary<string, List<uint>>>(
					File.ReadAllText("../filteredInsns.json"));
			var done = false;
			var insnQueue = new ConcurrentQueue<(FileStream, uint)>();
			var writeQueue = new ConcurrentQueue<(FileStream, uint, byte[])>();

			foreach(var (mnem, insns) in allInsns) {
				var fp = File.Create($"../unicornResults/{mnem}.bin");
				foreach(var insn in insns)
					insnQueue.Enqueue((fp, insn));
			}

			var completed = 0;
			var writer = new Thread(() => {
				while(!done) {
					if(!writeQueue.TryDequeue(out var elem)) {
						Thread.Sleep(10);
						continue;
					}

					var (fp, insn, buffer) = elem;
					fp.WriteByte((byte) ((insn >> 0) & 0xFF));
					fp.WriteByte((byte) ((insn >> 8) & 0xFF));
					fp.WriteByte((byte) ((insn >> 16) & 0xFF));
					fp.WriteByte((byte) ((insn >> 24) & 0xFF));
					using var mstream = new MemoryStream();
					using(var gzStream = new GZipStream(mstream, CompressionLevel.Fastest)) {
						gzStream.Write(buffer, 0, buffer.Length);
						gzStream.Flush();
					}
					var cbuf = mstream.ToArray();
					var csize = cbuf.Length;
					fp.WriteByte((byte) ((csize >> 0) & 0xFF));
					fp.WriteByte((byte) ((csize >> 8) & 0xFF));
					fp.WriteByte((byte) ((csize >> 16) & 0xFF));
					fp.WriteByte((byte) ((csize >> 24) & 0xFF));
					fp.Write(cbuf, 0, csize);
					completed++;
					if((completed % 100) == 0)
						Console.WriteLine($"Completed {completed} instructions!");
				}
			});
			writer.Start();

			var pool = 30;
			Enumerable.Range(0, pool).Select(i => {
				var thread = new Thread(() => {
					var server = new TcpListener(IPAddress.Loopback, 31337 + i);
					server.Start(2);
					insnQueue.TryDequeue(out var curInsn);
					var tries = 0;
					var lbytes = new byte[4];
					while(!insnQueue.IsEmpty || curInsn.Item1 != null) {
						var process = Process.Start("dotnet", $"run --no-build -c Release {31337 + i}");
						var client = server.AcceptSocket();
						SendAll(client, BitConverter.GetBytes(curInsn.Item2));
						var processed = 0;
						try {
							while(true) {
								if(process.HasExited || !client.Connected)
									throw new Exception();
								if(client.Available == 0) {
									Thread.Sleep(10);
									continue;
								}
								RecvAll(client, lbytes);
								var len = BitConverter.ToInt32(lbytes);
								if(len != 0) {
									var buf = new byte[len];
									RecvAll(client, buf);
									writeQueue.Enqueue((curInsn.Item1, curInsn.Item2, buf));
								}
								processed++;
								if(!insnQueue.TryDequeue(out curInsn))
									return;
								SendAll(client, BitConverter.GetBytes(curInsn.Item2));
							}
						} catch(Exception) {
							if(processed == 0 && ++tries == 5) {
								Console.WriteLine($"Bad instruction? 0x{curInsn.Item2:X8}");
								curInsn = (null, 0);
								tries = 0;
							}
						}
					}
				});
				thread.Start();
				return thread;
			}).ToList().ForEach(thread => thread.Join());
			done = true;
			writer.Join();
		}

		static void StartClient(int port) {
			var client = new TcpClient("localhost", port).Client;
			var insnBytes = new byte[4];
			var outputBuffer = new byte[16384];
			fixed(byte* mem = new byte[0x2000]) {
				var amem = (ulong) mem;
				if((amem & 0xFFF) != 0)
					amem = (amem & ~0xFFFUL) + 0x1000;
				var mp = (uint*) amem;
				for(var i = 0; i < 100; ++i) {
					RecvAll(client, insnBytes);
					var insn = BitConverter.ToUInt32(insnBytes);
					
					var outputOffset = 0;
					fixed(byte* ob = outputBuffer)
						foreach(var tc in baselineStates)
							fixed(byte* testCase = tc)
								outputOffset = TestOne(insn, mp, testCase, ob, outputOffset);
					SendAll(client, BitConverter.GetBytes(outputOffset));
					SendAll(client, outputBuffer, outputOffset);
				}
			}
		}

		static int TestOne(uint insn, uint* mem, byte* testCase, byte* outputState, int outputOffset) {
			var uc = new UnicornArm64 { [Arm64Register.CPACR_EL1] = 3 << 20 };
			uc.Map(0x1_0000_0000, 0x1000, MemoryPermission.All, (IntPtr) mem);
			mem[0] = insn;
			mem[1] = 0xD503201F;

			SetState(uc, testCase);
			try {
				uc.Start(0x1_0000_0000, 0x1_0000_0004, count: 1);
			} catch(UnicornException) {
				if(uc[Arm64Register.PC] == 0x1_0000_0000) {
					Console.WriteLine($"Failed on insn 0x{insn:X8}");
					return outputOffset;
				}
			}

			return GetStateDelta(uc, testCase, outputState, outputOffset);
		}

		static int GetStateDelta(UnicornArm64 uc, byte* testCase, byte* outputState, int outputOffset) {
			var i = outputOffset;

			void CheckV(Arm64Register reg, int tcOffset) {
				var val = uc.GetLarge(reg);
				var cmp = *(UInt128*) (testCase + tcOffset);
				if(val != cmp) {
					outputState[i] = 1;
					*(UInt128*) (outputState + i + 1) = val ^ cmp;
					i += 17;
				} else
					outputState[i++] = 0;
			}

			void CheckX(Arm64Register reg, int tcOffset) {
				var val = uc[reg];
				var cmp = *(ulong*) (testCase + tcOffset);
				if(val != cmp) {
					outputState[i] = 1;
					*(ulong*) (outputState + i + 1) = val ^ cmp;
					i += 9;
				} else
					outputState[i++] = 0;
			}
			
			void CheckC(Arm64Register reg, ulong cmp) {
				var val = uc[reg];
				if(val != cmp) {
					outputState[i] = 1;
					*(ulong*) (outputState + i + 1) = val ^ cmp;
					i += 9;
				} else
					outputState[i++] = 0;
			}
			
			CheckV(Arm64Register.V0, 0);
			CheckV(Arm64Register.V1, 16);
			CheckV(Arm64Register.V2, 32);
			CheckV(Arm64Register.V3, 48);
			CheckV(Arm64Register.V4, 64);
			CheckV(Arm64Register.V5, 80);
			CheckV(Arm64Register.V6, 96);
			CheckV(Arm64Register.V7, 112);
			CheckV(Arm64Register.V8, 128);
			CheckV(Arm64Register.V9, 144);
			CheckV(Arm64Register.V10, 160);
			CheckV(Arm64Register.V11, 176);
			CheckV(Arm64Register.V12, 192);
			CheckV(Arm64Register.V13, 208);
			CheckV(Arm64Register.V14, 224);
			CheckV(Arm64Register.V15, 240);
			CheckV(Arm64Register.V16, 256);
			CheckV(Arm64Register.V17, 272);
			CheckV(Arm64Register.V18, 288);
			CheckV(Arm64Register.V19, 304);
			CheckV(Arm64Register.V20, 320);
			CheckV(Arm64Register.V21, 336);
			CheckV(Arm64Register.V22, 352);
			CheckV(Arm64Register.V23, 368);
			CheckV(Arm64Register.V24, 384);
			CheckV(Arm64Register.V25, 400);
			CheckV(Arm64Register.V26, 416);
			CheckV(Arm64Register.V27, 432);
			CheckV(Arm64Register.V28, 448);
			CheckV(Arm64Register.V29, 464);
			CheckV(Arm64Register.V30, 480);
			CheckV(Arm64Register.V31, 496);
			
			CheckX(Arm64Register.X0, 512 + 0);
			CheckX(Arm64Register.X1, 512 + 8);
			CheckX(Arm64Register.X2, 512 + 16);
			CheckX(Arm64Register.X3, 512 + 24);
			CheckX(Arm64Register.X4, 512 + 32);
			CheckX(Arm64Register.X5, 512 + 40);
			CheckX(Arm64Register.X6, 512 + 48);
			CheckX(Arm64Register.X7, 512 + 56);
			CheckX(Arm64Register.X8, 512 + 64);
			CheckX(Arm64Register.X9, 512 + 72);
			CheckX(Arm64Register.X10, 512 + 80);
			CheckX(Arm64Register.X11, 512 + 88);
			CheckX(Arm64Register.X12, 512 + 96);
			CheckX(Arm64Register.X13, 512 + 104);
			CheckX(Arm64Register.X14, 512 + 112);
			CheckX(Arm64Register.X15, 512 + 120);
			CheckX(Arm64Register.X16, 512 + 128);
			CheckX(Arm64Register.X17, 512 + 136);
			CheckX(Arm64Register.X18, 512 + 144);
			CheckX(Arm64Register.X19, 512 + 152);
			CheckX(Arm64Register.X20, 512 + 160);
			CheckX(Arm64Register.X21, 512 + 168);
			CheckX(Arm64Register.X22, 512 + 176);
			CheckX(Arm64Register.X23, 512 + 184);
			CheckX(Arm64Register.X24, 512 + 192);
			CheckX(Arm64Register.X25, 512 + 200);
			CheckX(Arm64Register.X26, 512 + 208);
			CheckX(Arm64Register.X27, 512 + 216);
			CheckX(Arm64Register.X28, 512 + 224);
			CheckX(Arm64Register.X29, 512 + 232);
			CheckX(Arm64Register.X30, 512 + 240);

			var nzcvDelta = (uc[Arm64Register.NZCV] >> 28) ^ testCase[512 + 248];
			outputState[i++] = (byte) nzcvDelta;

			CheckC(Arm64Register.PC, 0x1_0000_0000);
			CheckC(Arm64Register.SP, 0x7_ffff_ff00);

			return i;
		}

		static void SetState(UnicornArm64 uc, byte* testCase) {
			uc.SetLarge(Arm64Register.V0, *(UInt128*) (testCase + 0));
			uc.SetLarge(Arm64Register.V1, *(UInt128*) (testCase + 16));
			uc.SetLarge(Arm64Register.V2, *(UInt128*) (testCase + 32));
			uc.SetLarge(Arm64Register.V3, *(UInt128*) (testCase + 48));
			uc.SetLarge(Arm64Register.V4, *(UInt128*) (testCase + 64));
			uc.SetLarge(Arm64Register.V5, *(UInt128*) (testCase + 80));
			uc.SetLarge(Arm64Register.V6, *(UInt128*) (testCase + 96));
			uc.SetLarge(Arm64Register.V7, *(UInt128*) (testCase + 112));
			uc.SetLarge(Arm64Register.V8, *(UInt128*) (testCase + 128));
			uc.SetLarge(Arm64Register.V9, *(UInt128*) (testCase + 144));
			uc.SetLarge(Arm64Register.V10, *(UInt128*) (testCase + 160));
			uc.SetLarge(Arm64Register.V11, *(UInt128*) (testCase + 176));
			uc.SetLarge(Arm64Register.V12, *(UInt128*) (testCase + 192));
			uc.SetLarge(Arm64Register.V13, *(UInt128*) (testCase + 208));
			uc.SetLarge(Arm64Register.V14, *(UInt128*) (testCase + 224));
			uc.SetLarge(Arm64Register.V15, *(UInt128*) (testCase + 240));
			uc.SetLarge(Arm64Register.V16, *(UInt128*) (testCase + 256));
			uc.SetLarge(Arm64Register.V17, *(UInt128*) (testCase + 272));
			uc.SetLarge(Arm64Register.V18, *(UInt128*) (testCase + 288));
			uc.SetLarge(Arm64Register.V19, *(UInt128*) (testCase + 304));
			uc.SetLarge(Arm64Register.V20, *(UInt128*) (testCase + 320));
			uc.SetLarge(Arm64Register.V21, *(UInt128*) (testCase + 336));
			uc.SetLarge(Arm64Register.V22, *(UInt128*) (testCase + 352));
			uc.SetLarge(Arm64Register.V23, *(UInt128*) (testCase + 368));
			uc.SetLarge(Arm64Register.V24, *(UInt128*) (testCase + 384));
			uc.SetLarge(Arm64Register.V25, *(UInt128*) (testCase + 400));
			uc.SetLarge(Arm64Register.V26, *(UInt128*) (testCase + 416));
			uc.SetLarge(Arm64Register.V27, *(UInt128*) (testCase + 432));
			uc.SetLarge(Arm64Register.V28, *(UInt128*) (testCase + 448));
			uc.SetLarge(Arm64Register.V29, *(UInt128*) (testCase + 464));
			uc.SetLarge(Arm64Register.V30, *(UInt128*) (testCase + 480));
			uc.SetLarge(Arm64Register.V31, *(UInt128*) (testCase + 496));
			uc[Arm64Register.X0] = *(ulong*) (testCase + 512 + 0);
			uc[Arm64Register.X1] = *(ulong*) (testCase + 512 + 8);
			uc[Arm64Register.X2] = *(ulong*) (testCase + 512 + 16);
			uc[Arm64Register.X3] = *(ulong*) (testCase + 512 + 24);
			uc[Arm64Register.X4] = *(ulong*) (testCase + 512 + 32);
			uc[Arm64Register.X5] = *(ulong*) (testCase + 512 + 40);
			uc[Arm64Register.X6] = *(ulong*) (testCase + 512 + 48);
			uc[Arm64Register.X7] = *(ulong*) (testCase + 512 + 56);
			uc[Arm64Register.X8] = *(ulong*) (testCase + 512 + 64);
			uc[Arm64Register.X9] = *(ulong*) (testCase + 512 + 72);
			uc[Arm64Register.X10] = *(ulong*) (testCase + 512 + 80);
			uc[Arm64Register.X11] = *(ulong*) (testCase + 512 + 88);
			uc[Arm64Register.X12] = *(ulong*) (testCase + 512 + 96);
			uc[Arm64Register.X13] = *(ulong*) (testCase + 512 + 104);
			uc[Arm64Register.X14] = *(ulong*) (testCase + 512 + 112);
			uc[Arm64Register.X15] = *(ulong*) (testCase + 512 + 120);
			uc[Arm64Register.X16] = *(ulong*) (testCase + 512 + 128);
			uc[Arm64Register.X17] = *(ulong*) (testCase + 512 + 136);
			uc[Arm64Register.X18] = *(ulong*) (testCase + 512 + 144);
			uc[Arm64Register.X19] = *(ulong*) (testCase + 512 + 152);
			uc[Arm64Register.X20] = *(ulong*) (testCase + 512 + 160);
			uc[Arm64Register.X21] = *(ulong*) (testCase + 512 + 168);
			uc[Arm64Register.X22] = *(ulong*) (testCase + 512 + 176);
			uc[Arm64Register.X23] = *(ulong*) (testCase + 512 + 184);
			uc[Arm64Register.X24] = *(ulong*) (testCase + 512 + 192);
			uc[Arm64Register.X25] = *(ulong*) (testCase + 512 + 200);
			uc[Arm64Register.X26] = *(ulong*) (testCase + 512 + 208);
			uc[Arm64Register.X27] = *(ulong*) (testCase + 512 + 216);
			uc[Arm64Register.X28] = *(ulong*) (testCase + 512 + 224);
			uc[Arm64Register.X29] = *(ulong*) (testCase + 512 + 232);
			uc[Arm64Register.X30] = *(ulong*) (testCase + 512 + 240);

			uc[Arm64Register.NZCV] = (ulong) testCase[512 + 248] << 28;

			uc[Arm64Register.PC] = 0x1_0000_0000;
			uc[Arm64Register.SP] = 0x7_ffff_ff00;
		}
	}
}