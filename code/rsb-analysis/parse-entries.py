import subprocess
import matplotlib.pyplot as plt
import re

subprocess.run("make", stdout=subprocess.PIPE).check_returncode()

out = subprocess.check_output("./get-rsb-entries").decode().splitlines()

freqs = []
for line in out:
	line_freq = {}
	for match in re.finditer(r"(\d+)\:\s*(\d+)", line):
		entry = int(match.group(1))
		freq = int(match.group(2))
		line_freq[entry] = freq
	freqs.append(line_freq)

keys = list(range(max(max(i) for i in freqs) + 5))

x_vals = []
y_vals = []
sizes = []

for i, d in enumerate(freqs):
	for key in d:
		freq = d[key]
		x_vals.append(i)
		y_vals.append(key)
		sizes.append(min(100, freq * 20))

# Plot
plt.figure()
plt.scatter(x_vals, y_vals, s=sizes)  # , alpha=0.6)
plt.yticks(range(len(keys)), keys)  # Show key names on y-axis
plt.xticks(range(65), range(65))  # Show key names on y-axis
plt.xlabel("Target ret")
plt.ylabel("Used rsb entry")
plt.grid(True)
plt.show()
