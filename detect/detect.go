package detect

import (
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/yzpgryx/randomness"
)

const (
	LogInfo = 6
	LogDebug
)

type TestReporter interface {
	LogReporter(level int, format string, args ...interface{})
}

func createDistributions(s, m int) [][]float64 {
	res := make([][]float64, m)
	for i := 0; i < m; i++ {
		res[i] = make([]float64, s)
	}
	return res
}

// FactoryDetect 出厂检测，15种检测，每组 10^6比特，分50组
// source: 随机源
func FactoryDetect(source io.Reader) (bool, error) {
	s := 50
	t := Threshold(s)
	buf := make([]byte, 1000000/8)
	counters := make([]int, 15)
	distributions := createDistributions(s, 15)
	for i := 0; i < s; i++ {
		_, err := io.ReadFull(source, buf)
		if err != nil {
			return false, err
		}
		resArr := Round15(buf)
		for idx, result := range resArr {
			distributions[idx][i] = result.Q
			if result.Pass {
				counters[idx]++
			}
		}
	}
	for i, n := range counters {
		if n < t {
			return false, fmt.Errorf("%s %d/%d", randomness.TestMethodArr[i].Name, n, s)
		}
	}
	for i := range distributions {
		Pt := ThresholdQ(distributions[i])
		if Pt < randomness.AlphaT {
			return false, fmt.Errorf("%s %f", randomness.TestMethodArr[i].Name, Pt)
		}
	}
	return true, nil
}

// PowerOnDetect 上电自检，15种检测，每组 10^6比特，分20组
// source: 随机源
func PowerOnDetect(source io.Reader, reporter TestReporter) (bool, error) {
	s := 20
	t := Threshold(s)
	buf := make([]byte, 1000000/8)
	counters := make([]int, 15)
	distributions := createDistributions(s, 15)

	reporter.LogReporter(LogInfo, "随机数上电检测开始, %d组, 每组10^6bits\n", s);

	for i := 0; i < s; i++ {
		_, err := io.ReadFull(source, buf)
		if err != nil {
			return false, err
		}
		resArr := Round15(buf)
		for idx, result := range resArr {
			distributions[idx][i] = result.Q
			if result.Pass {
				counters[idx]++
			}
			reporter.LogReporter(LogDebug, "第%02d组, [%s], p : %.4f, q : %.4f", i + 1, result.Name, result.P, result.Q)
		}
	}
	for i, n := range counters {
		reporter.LogReporter(LogInfo, "[%s], 样本 : %d, 通过 : %d, 通过阈值 : %d, 通过率 : %.2f\n",
			randomness.TestMethodArr[i].Name, s, n, t, (float64(n) / float64(s)) * 100)
		if n < t {
			return false, fmt.Errorf("%s %d/%d", randomness.TestMethodArr[i].Name, n, s)
		}
	}
	for i := range distributions {
		Pt := ThresholdQ(distributions[i])
		reporter.LogReporter(LogInfo,"[%s], Pt : %.2f\n", randomness.TestMethodArr[i].Name, Pt)
		if Pt < randomness.AlphaT {
			return false, fmt.Errorf("%s %f", randomness.TestMethodArr[i].Name, Pt)
		}
	}
	return true, nil
}

// PeriodDetect 周期性检测，除去离散傅里叶检测、线型复杂度检测、通用统计的12种检测
// 检测 20组，每组 20000比特
// source: 随机源
func PeriodDetect(source io.Reader, reporter TestReporter) (bool, error) {
	s := 20
	t := Threshold(s)
	buf := make([]byte, 20000/8)
	counters := make([]int, 12)
	distributions := createDistributions(s, 12)

	reporter.LogReporter(LogInfo, "随机数周期性检测开始, %d组, 每组%dbits\n", s, 20000);

	for i := 0; i < s; i++ {
		_, err := io.ReadFull(source, buf)
		if err != nil {
			return false, err
		}
		resArr := Round12(buf)
		for idx, result := range resArr {
			distributions[idx][i] = result.Q
			if result.Pass {
				counters[idx]++
			}
			reporter.LogReporter(LogDebug, "第%02d组, [%s], p : %.4f, q : %.4f", i + 1, result.Name, result.P, result.Q)
		}
	}
	for i, n := range counters {
		reporter.LogReporter(LogInfo, "[%s], 样本 : %d, 通过 : %d, 通过阈值 : %d, 通过率 : %.2f\n",
			randomness.TestMethodArr[i].Name, s, n, t, (float64(n) / float64(s)) * 100)
		if n < t {
			return false, fmt.Errorf("%s %d/%d", randomness.TestMethodArr[i].Name, n, s)
		}
	}

	for i := range distributions {
		Pt := ThresholdQ(distributions[i])
		reporter.LogReporter(LogInfo,"[%s], Pt : %.2f\n", randomness.TestMethodArr[i].Name, Pt)
		if Pt < randomness.AlphaT {
			return false, fmt.Errorf("%s %f", randomness.TestMethodArr[i].Name, Pt)
		}
	}
	return true, nil
}

// SingleDetect 单次检测，单根据实际应用时每次才随机数的大小确定，检测采用扑克检测
// source: 随机源
// numByte: 采集字节数，不能小于16
func SingleDetect(source io.Reader, numByte int, reporter TestReporter) (bool, error) {
	data := make([]byte, numByte)

	reporter.LogReporter(LogInfo, "随机数单次检测开始,测试长度 : %d bits\n", numByte * 8)

	_, err := io.ReadFull(source, data)
	if err != nil {
		return false, err
	}
	n := len(data) * 8
	if n < 128 {
		return false, errors.New("长度不能低于128比特（16 byte）")
	}
	m := 4
	if n < 320 {
		m = 2
	} else if n/8 >= 1280 { // n/m >= 5 * 2^m
		m = 8
	}
	p, _ := randomness.PokerTestBytes(data, m)
	reporter.LogReporter(LogInfo, "单次检测结束,测试长度 : %d bits, p : %f\n", numByte * 8, p)

	if p < randomness.Alpha {
		p += randomness.Alpha
	}

	return p >= randomness.Alpha, nil
}

// Threshold 样本通过检测判定数量
// s: 检测样本数
// return 通过检测需要的样本数量
func Threshold(s int) int {
	a := randomness.Alpha
	_s := float64(s)
	r := _s * (1 - a - 3*math.Sqrt((a*(1-a))/_s))

	return int(math.Ceil(r))
}

// ThresholdQ 样本分布均匀性 (k=10)
func ThresholdQ(qValues []float64) float64 {
	var dist [10]int
	for _, q := range qValues {
		switch {
		case q < 0.1:
			dist[0]++
		case q < 0.2:
			dist[1]++
		case q < 0.3:
			dist[2]++
		case q < 0.4:
			dist[3]++
		case q < 0.5:
			dist[4]++
		case q < 0.6:
			dist[5]++
		case q < 0.7:
			dist[6]++
		case q < 0.8:
			dist[7]++
		case q < 0.9:
			dist[8]++
		default:
			dist[9]++
		}
	}
	var V float64 = 0
	sk := float64(len(qValues)) / 10
	for i := 0; i < 10; i++ {
		V += (float64(dist[i]) - sk) * (float64(dist[i]) - sk) / sk
	}
	return randomness.Igamc(4.5, V/2)
}
