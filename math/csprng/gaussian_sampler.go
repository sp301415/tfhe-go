package csprng

import (
	"math"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
)

// GaussianSampler samples from Rounded Gaussian Distribution, centered around zero.
type GaussianSampler[T num.Integer] struct {
	baseSampler *UniformSampler[uint32]
}

// NewGaussianSampler allocates an empty GaussianSampler.
//
// Panics when read from crypto/rand or blake2b initialization fails.
func NewGaussianSampler[T num.Integer]() *GaussianSampler[T] {
	return &GaussianSampler[T]{
		baseSampler: NewUniformSampler[uint32](),
	}
}

// NewGaussianSamplerWithSeed allocates an empty GaussianSampler, with user supplied seed.
//
// Panics when blake2b initialization fails.
func NewGaussianSamplerWithSeed[T num.Integer](seed []byte, stdDev float64) *GaussianSampler[T] {
	return &GaussianSampler[T]{
		baseSampler: NewUniformSamplerWithSeed[uint32](seed),
	}
}

// uniformFloat samples float32 (as float64) from uniform distribution in [0, 1).
func (s *GaussianSampler[T]) uniformFloat() float64 {
	return float64(float32(s.baseSampler.Sample()>>9) * (1.0 / (1 << 23)))
}

// normFloat samples float64 from normal distribution.
func (s *GaussianSampler[T]) normFloat() float64 {
	for {
		var x, y float64

		h := s.baseSampler.Sample()
		t := h & 1
		i := (h >> 1) & 127
		u := h >> 8

		x = float64(u) * wn[i]
		if t > 0 {
			x = -x
		}

		if u < kn[i] {
			return x
		}

		if i == 0 {
			for {
				x = -rnInv * math.Log(s.uniformFloat())
				y = -math.Log(s.uniformFloat())
				if y+y >= x*x {
					break
				}
			}
			x += rn

			if t > 0 {
				return -x
			}
			return x
		}

		if fn[i]+s.uniformFloat()*(fn[i-1]-fn[i]) < math.Exp(-0.5*x*x) {
			return x
		}
	}
}

// Sample returns a number sampled from rounded gaussian distribution
// with standard deviation stdDev.
//
// Panics when stdDev < 0.
func (s *GaussianSampler[T]) Sample(stdDev float64) T {
	if stdDev < 0 {
		panic("standard deviation not positive")
	}

	return T(int64(math.Round(s.normFloat() * stdDev)))
}

// SampleSliceAssign samples rounded gaussian values
// with standard deviation stdDev, and writes it to vOut.
//
// Panics when stdDev < 0.
func (s *GaussianSampler[T]) SampleSliceAssign(stdDev float64, vOut []T) {
	if stdDev < 0 {
		panic("standard deviation not positive")
	}

	for i := range vOut {
		vOut[i] = T(int64(math.Round(s.normFloat() * stdDev)))
	}
}

// SamplePolyAssign samples rounded gaussian values
// with standard deviation stdDev, and writes it to pOut.
//
// Panics when stdDev < 0.
func (s *GaussianSampler[T]) SamplePolyAssign(stdDev float64, pOut poly.Poly[T]) {
	s.SampleSliceAssign(stdDev, pOut.Coeffs)
}

// SamplePolyAddAssign samples rounded gaussian values
// with standard deviation stdDev, and adds to pOut.
//
// Panics when stdDev < 0.
func (s *GaussianSampler[T]) SamplePolyAddAssign(stdDev float64, pOut poly.Poly[T]) {
	if stdDev < 0 {
		panic("standard deviation not positive")
	}

	for i := range pOut.Coeffs {
		pOut.Coeffs[i] += T(int64(math.Round(s.normFloat() * stdDev)))
	}
}

// SamplePolySubAssign samples rounded gaussian values
// with standard deviation stdDev, and subtracts from pOut.
//
// Panics when stdDev < 0.
func (s *GaussianSampler[T]) SamplePolySubAssign(stdDev float64, pOut poly.Poly[T]) {
	if stdDev < 0 {
		panic("standard deviation not positive")
	}

	for i := range pOut.Coeffs {
		pOut.Coeffs[i] -= T(int64(math.Round(s.normFloat() * stdDev)))
	}
}

/* Constants Generated by:
const (
	blockSize = 128
	scale     = 1 << 24
)

var (
	wn [128]float64
	kn [128]uint32
	fn [128]float64

	dn = 3.442619855899
	vn = 9.91256303526217e-3
)

q := vn / math.Exp(-.5*dn*dn)

kn[0] = uint32(math.Round((dn / q) * scale))
kn[1] = 0

wn[0] = q / scale
wn[127] = dn / scale

fn[0] = 1.0
fn[127] = math.Exp(-.5 * dn * dn)

tn := dn
for i := 126; i >= 1; i-- {
	dn = math.Sqrt(-2.0 * math.Log(vn/dn+math.Exp(-.5*dn*dn)))
	kn[i+1] = uint32((dn / tn) * scale)
	tn = dn
	wn[i] = dn / scale
	fn[i] = math.Exp(-.5 * dn * dn)
}
*/

var (
	rn    = 3.442619855899
	rnInv = 1 / rn
	kn    = [128]uint32{
		0xed5a44, 0x0, 0xc01e36, 0xd9c88f,
		0xe4b68d, 0xeac00a, 0xee9243, 0xf1344b,
		0xf3208b, 0xf4979c, 0xf5bec5, 0xf6ad05,
		0xf77151, 0xf815ce, 0xf8a199, 0xf919d8,
		0xf98259, 0xf9ddfd, 0xfa2efc, 0xfa7711,
		0xfab79c, 0xfaf1ba, 0xfb2651, 0xfb561c,
		0xfb81ba, 0xfba9ad, 0xfbce63, 0xfbf039,
		0xfc0f81, 0xfc2c7d, 0xfc476b, 0xfc607b,
		0xfc77dd, 0xfc8db6, 0xfca22a, 0xfcb557,
		0xfcc757, 0xfcd844, 0xfce832, 0xfcf734,
		0xfd055b, 0xfd12b8, 0xfd1f58, 0xfd2b47,
		0xfd3692, 0xfd4141, 0xfd4b60, 0xfd54f5,
		0xfd5e09, 0xfd66a4, 0xfd6ecb, 0xfd7684,
		0xfd7dd5, 0xfd84c4, 0xfd8b53, 0xfd9188,
		0xfd9766, 0xfd9cf1, 0xfda22c, 0xfda71a,
		0xfdabbe, 0xfdb019, 0xfdb42e, 0xfdb800,
		0xfdbb8f, 0xfdbedd, 0xfdc1ec, 0xfdc4bd,
		0xfdc751, 0xfdc9a8, 0xfdcbc4, 0xfdcda5,
		0xfdcf4c, 0xfdd0b8, 0xfdd1e9, 0xfdd2e0,
		0xfdd39c, 0xfdd41d, 0xfdd462, 0xfdd46a,
		0xfdd435, 0xfdd3c0, 0xfdd30c, 0xfdd215,
		0xfdd0da, 0xfdcf58, 0xfdcd8e, 0xfdcb79,
		0xfdc914, 0xfdc65d, 0xfdc350, 0xfdbfe8,
		0xfdbc1f, 0xfdb7f1, 0xfdb357, 0xfdae49,
		0xfda8bf, 0xfda2b0, 0xfd9c12, 0xfd94d9,
		0xfd8cf7, 0xfd845d, 0xfd7afa, 0xfd70b8,
		0xfd6580, 0xfd5938, 0xfd4bbe, 0xfd3ced,
		0xfd2c98, 0xfd1a89, 0xfd0680, 0xfcf02e,
		0xfcd732, 0xfcbb14, 0xfc9b3b, 0xfc76e6,
		0xfc4d18, 0xfc1c7f, 0xfbe354, 0xfb9f18,
		0xfb4c34, 0xfae541, 0xfa61c1, 0xf9b369,
		0xf8c01e, 0xf75217, 0xf4e442, 0xefacc9,
	}
	wn = [128]float64{
		2.2131718675747815e-07, 1.6231588412162755e-08, 2.162882274967572e-08, 2.5424241206372792e-08,
		2.8457512694399618e-08, 3.1033518240574354e-08, 3.33006488328088e-08, 3.534334555098084e-08,
		3.721467240667625e-08, 3.895036213040186e-08, 4.0575737873861284e-08, 4.210946627470455e-08,
		4.3565744795947436e-08, 4.4955650833490674e-08, 4.6288012736723265e-08, 4.756999377274838e-08,
		4.880749623181551e-08, 5.000544871673435e-08, 5.116801519357031e-08, 5.229875022845991e-08,
		5.340071633940549e-08, 5.447657412427841e-08, 5.552865246624638e-08, 5.655900392003678e-08,
		5.7569448912212094e-08, 5.856161138507287e-08, 5.953694781619198e-08, 6.049677105255892e-08,
		6.144227004457674e-08, 6.237452630782386e-08, 6.329452775089875e-08, 6.420318036633099e-08,
		6.510131817503429e-08, 6.598971173370091e-08, 6.686907545224076e-08, 6.774007392008063e-08,
		6.860332740240491e-08, 6.945941663770386e-08, 7.030888704442901e-08, 7.115225242573783e-08,
		7.198999824618987e-08, 7.282258454203579e-08, 7.365044851680766e-08, 7.447400686580345e-08,
		7.529365786639572e-08, 7.610978326559989e-08, 7.692274999178623e-08, 7.773291171363688e-08,
		7.85406102662929e-08, 7.934617696199576e-08, 8.014993380031266e-08, 8.09521945911731e-08,
		8.17532660023774e-08, 8.255344854191848e-08, 8.335303748434811e-08, 8.415232374948604e-08,
		8.495159474099038e-08, 8.575113515165824e-08, 8.655122774179126e-08, 8.735215409652654e-08,
		8.815419536768938e-08, 8.895763300546134e-08, 8.976274948496838e-08, 9.056982903277516e-08,
		9.137915835821887e-08, 9.219102739452782e-08, 9.300573005474621e-08, 9.382356500762706e-08,
		9.464483647886372e-08, 9.54698550833093e-08, 9.629893869418865e-08, 9.713241335574595e-08,
		9.797061424630097e-08, 9.881388669932032e-08, 9.966258729085928e-08, 1.0051708500261117e-07,
		1.0137776247083645e-07, 1.0224501733265326e-07, 1.0311926368258777e-07, 1.0400093365393879e-07,
		1.0489047914144954e-07, 1.0578837368405278e-07, 1.066951145291244e-07, 1.0761122490282227e-07,
		1.0853725651479514e-07, 1.0947379232993399e-07, 1.1042144964504784e-07, 1.1138088351455262e-07,
		1.1235279057668203e-07, 1.1333791334063715e-07, 1.1433704500582873e-07, 1.1535103489736455e-07,
		1.1638079461774568e-07, 1.1742730503406087e-07, 1.1849162424371361e-07, 1.1957489669105244e-07,
		1.2067836364372882e-07, 1.218033752831857e-07, 1.2295140472104004e-07, 1.2412406432581048e-07,
		1.2532312483723393e-07, 1.2655053786480287e-07, 1.2780846252205344e-07, 1.2909929715090525e-07,
		1.3042571735835368e-07, 1.3179072194568535e-07, 1.3319768879359838e-07, 1.346504434269189e-07,
		1.3615334389671515e-07, 1.3771138690106648e-07, 1.3933034189577322e-07, 1.4101692260012857e-07,
		1.427790092236437e-07, 1.4462594065271317e-07, 1.4656890496086064e-07, 1.4862147105308605e-07,
		1.5080032780103847e-07, 1.5312633668928968e-07, 1.5562607338618323e-07, 1.5833416052230356e-07,
		1.6129693824778912e-07, 1.6457851960582595e-07, 1.6827138367586794e-07, 1.7251634639629894e-07,
		1.7754413203285815e-07, 1.8377476085524966e-07, 1.921108355868543e-07, 2.0519613360756637e-07,
	}
	fn = [128]float64{
		1, 0.9635996931270896, 0.9362826816850625, 0.9130436479717428,
		0.8922816507840284, 0.8732430489100717, 0.8555006078694526, 0.8387836052959915,
		0.8229072113814108, 0.8077382946829622, 0.7931770117713067, 0.7791460859296893,
		0.765584173897706, 0.7524415591746129, 0.7396772436726488, 0.7272569183441863,
		0.7151515074105, 0.7033360990161595, 0.6917891434366764, 0.6804918409973354,
		0.6694276673488917, 0.6585820000500895, 0.647941821110224, 0.6374954773350439,
		0.6272324852499288, 0.6171433708188824, 0.6072195366251217, 0.5974531509445181,
		0.5878370544347078, 0.5783646811197644, 0.569029991067952, 0.5598274127040879,
		0.5507517931146054, 0.5417983550254263, 0.5329626593838369, 0.5242405726729849,
		0.5156282382440026, 0.5071220510755696, 0.49871863547098017, 0.4904148252838448,
		0.4822076463294858, 0.47409430069301745, 0.4660721526894566, 0.4581387162678725,
		0.4502916436820397, 0.44252871527546894, 0.4348478302499913, 0.42724699830499646,
		0.41972433204957477, 0.4122780401026614, 0.40490642080722333, 0.39760785649387365,
		0.39038080823731486, 0.38322381105590136, 0.3761354695105628, 0.36911445366447243,
		0.3621594953693178, 0.35526938484791737, 0.3484429675463268, 0.3416791412315506,
		0.33497685331358923, 0.3283350983728503, 0.3217529158759849, 0.31522938806501094,
		0.3087636380061812, 0.30235482778648354, 0.296002156846933, 0.28970486044295984,
		0.283462208223233, 0.2772735029191881, 0.2711380791383846, 0.2650553022555892,
		0.25902456739620483, 0.25304529850732577, 0.2471169475123214, 0.24123899354543982,
		0.23541094226347908, 0.22963232523211613, 0.22390269938500842, 0.21822164655430543,
		0.21258877307173027, 0.2070037094399266, 0.20146611007431373, 0.1959756531162778,
		0.19053204031913723, 0.18513499700899227, 0.17978427212329554, 0.17447963833078958,
		0.169220892237365, 0.16400785468342038, 0.1588403711394793, 0.15371831220818166,
		0.14864157424234226, 0.14361008009062776, 0.1386237799845946, 0.13368265258343937,
		0.1287867061959432, 0.12393598020286782, 0.11913054670765083, 0.11437051244886601,
		0.10965602101484027, 0.10498725540942132, 0.10036444102865587, 0.09578784912173144,
		0.09125780082683026, 0.08677467189478019, 0.08233889824223567, 0.0779509825139734,
		0.0736115018841134, 0.06932111739357791, 0.06508058521306807, 0.060890770348040406,
		0.05675266348104985, 0.052667401903051005, 0.048636295859867805, 0.044660862200491425,
		0.040742868074444175, 0.0368843887866562, 0.03308788614622575, 0.02935631744000685,
		0.02569329193593427, 0.022103304615927098, 0.018592102737011288, 0.015167298010546568,
		0.011839478657884862, 0.008624484412859885, 0.005548995220771345, 0.002669629083880923,
	}
)
