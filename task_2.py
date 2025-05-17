import mmh3
import math
import time
import json


class HyperLogLog:
    def __init__(self, p=5):
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        self.small_range_correction = 5 * self.m / 2

    def _get_alpha(self):
        if self.p <= 16:
            return 0.673
        elif self.p == 32:
            return 0.697
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def add(self, item):
        x = mmh3.hash(str(item), signed=False)
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    def _rho(self, w):
        return len(bin(w)) - 2 if w > 0 else 32

    def count(self):
        Z = sum(2.0**-r for r in self.registers)
        E = self.alpha * self.m * self.m / Z

        if E <= self.small_range_correction:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)

        return E


def load_data(file_path):
    ip_addresses = []
    with open(file_path, "r") as file:
        for line in file:
            try:
                log_entry = json.loads(line.strip())
                if "remote_addr" in log_entry:
                    ip_addresses.append(log_entry["remote_addr"])
            except json.JSONDecodeError:
                continue
    return ip_addresses


def exact_count(ip_addresses):
    return len(set(ip_addresses))


def approximate_count(ip_addresses):
    hll = HyperLogLog(p=14)
    for ip in ip_addresses:
        hll.add(ip)
    return hll.count()


if __name__ == "__main__":
    file_path = "lms-stage-access.log"
    ip_addresses = load_data(file_path)

    # Точний підрахунок
    start_time = time.time()
    exact_result = exact_count(ip_addresses)
    exact_time = time.time() - start_time

    # Наближений підрахунок
    start_time = time.time()
    approximate_result = approximate_count(ip_addresses)
    approximate_time = time.time() - start_time

    print("Результати порівняння:")
    print(f"{'Метод':<25}{'Унікальні елементи':<25}{'Час виконання (сек.)':<25}")
    print(f"{'Точний підрахунок':<25}{exact_result:<25}{exact_time:<25.5f}")
    print(f"{'HyperLogLog':<25}{approximate_result:<25.5f}{approximate_time:<25.5f}")
    error = abs(exact_result - approximate_result) / exact_result * 100
    print(f"{'Похибка (%)':<25}{error:<25.2f}")
