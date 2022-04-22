# Franklin-Reiter related message attack + Coppersmith short pad attack
# https://github.com/pwang00/Cryptographic-Attacks/blob/master/Public%20Key/RSA/coppersmith_short_pad.sage

from Crypto.Util.number import long_to_bytes
import random
import binascii

n = 823652328526060931201375649241006048943627312591742662481083103378002522077877852124731191042617160616707714556599692967069663667698601996983528940331840856212083763983210643933408040552418340463683380557808507002495230815546453104038740886365473259236836768987811419579308089803722619415774848441151249684528573808701348303730672001325400435253430057941264536553439343549378798471521843765967413899839467956313753964739101523564712402586172009670872793597148015854112713073516537134244622001863136944934492241145306737850771111625635504275979597201321615004183224138178242850606020061860874365891414739635021953470569531263648279914661978749409495850032838932287660547294983608500552408270453150111004704982673000064474229357303826290412232101668643442191345117752836713723186345029858940323602239828980619674790421554523298312252632246856653570861376722546483845572057592874642653507921669598604980999675710944351125800581153679737947035951167396427406664211538456926422574733908468243848301080202616710219948021550303624199272309262465841979895988543037749409344273271528685813232663250051559875409936374630801262025889212026998068310718442102601557388789291924368011403387710015947533663816312246609754580679612583443687679604653697210741383870120265666560114312552082718765229857906075466911647146394186461224534740685587572846934610230530077015354170886197688407248753878297395666994564903309464938353409270895657559261894379593177576322878056778321362020242262629594237747578073010697822390042229221755183530894661801846645578606229378188194698297341498164221255458973569036112042793665638020083355322818801649079577206155596664351547761867936241825962264402061264130743855926770190009644935373522637016531313612905118696369479379392748765790270985780979092810127202612369788297683386941277137962371308477169065442960974519121200614968578299255908217109555425373639991249942561881066593925137769635916819686179968920303847549317832449280869569173490086055713440659573036379376871313591502012736961740953226823792006776306025493582816361497869257717651668075570919074032100188984609089237083774415809378590512597855039607625398955711313352280354581208986236739705133090250836743923077744209886105632205516098409509945870967048379575392597005574605671295696290105152505109115729545462303929321064678575733744453013844396847747874774560936394947704938716022268449263762808882912779863563062087323815155503567025604594567944510834845389179609006394130719657363087
C1 = 138604270237134534112743212644616449187692378939637896055320936677529897960835117799077267347298678107031857708834234867949004008866584408288272718174944005247281182704110071985982762860316789278723189738430436690943806868878982562799129736576593875631850056775539229239799682738700710216806174002449616599477466210310386600736499714740361747969973718347095697189605303148613119104798603461313289164107162759182110107568729898709265252329895862170091572165860623096748730108315029720395180483240857815537765987240293780559413621634616731611457999105645890254616180108684484111551400204145466579713376335168837095473428132610657311922576659063964864816927637794472255883920363962994040086056352213615355155336047742875321877777043584327913192448537029767660816802421871457551873100279391823455263903450304034557919732645143487533538943198997776987742643929566403463889152262047049873409325737357390275038091407938919150758822963329761264354005399142689352595527066743969291045496548965996410916410974600827179080229802502026992567559903302198282019316525974045236753071662259094177004561587843521123352176047829889922474932560434065169177898287264496750729243672
C2 = 138604270237134534112743212644616449187692378939637896055320936677529897960835117799077267347298678107031857708834234867949004008866584408288272718174944005247281182704110071985982762860316789278723189738430436690943806868878982562801315565156426103645734001592666235894224346424366448014174339619953344112868374944069699668659552171905796026764359565068714399719527680623357405851675409955573477228301886561411896147227291350808930951282598922176120977605666135963906053158934308125639347521515926780372069545707019601637468577493997742590807146827349865640857651027809446746299962731018358206171079317925725680542147150070051957133849278906576405074966481232057919403951090124732230438431203080079109828298282999845576767904877434936923847105040157703725014937676457110907557409863930279230474134789746314617582331031090955073528453085567165286271224442421785911327002274933133905582320854345262688022854226418394665705506630780960278867388105443056536999414456768050350078505683642885335398895190922264436040594316438930099159076822113725497974332635130516805301785291427363314598707750026963533325470071715793252887081074252099626695293515248472454824781000
e = 3
BITSIZE =  8192
m = floor(BITSIZE / (e * e)) - 400

def coppersmith_short_pad(C1, C2, N, e = 3, eps = 1/25):
    P.<x, y> = PolynomialRing(Zmod(N))
    P2.<y> = PolynomialRing(Zmod(N))

    g1 = (x^e - C1).change_ring(P2)
    g2 = ((x + y)^e - C2).change_ring(P2)

    # Changes the base ring to Z_N[y] and finds resultant of g1 and g2 in x
    res = g1.resultant(g2, variable=x)

    # coppersmith's small_roots only works over univariate polynomial rings, so we
    # convert the resulting polynomial to its univariate form and take the coefficients modulo N
    # Then we can call the sage's small_roots function and obtain the delta between m_1 and m_2.
    # Play around with these parameters: (epsilon, beta, X)
    roots = res.univariate_polynomial().change_ring(Zmod(N)).small_roots(epsilon=eps)

    return roots[0]

def franklin_reiter(C1, C2, N, r, e = 3):
    P.<x> = PolynomialRing(Zmod(N))
    equations = [x^e - C1, (x + r)^e - C2]
    g1, g2 = equations
    return -composite_gcd(g1, g2).coefficients()[0]

def recover_message(C1, C2, N, e, m):
    delta = coppersmith_short_pad(C1, C2, N)
    return Integer(franklin_reiter(C1, C2, N, delta)) >> m

def composite_gcd(g1, g2):
    return g1.monic() if g2 == 0 else composite_gcd(g2, g1 % g2)

if __name__ == "__main__":
    flag = long_to_bytes(recover_message(C1, C2, n, e, m)).decode()
    assert flag == 'crew{l00ks_l1k3_y0u_h4v3_you_He4rd_0f_c0pp3rsm1th_sh0r+_p4d_4tt4ck_th4t_w45n\'t_d1ff1cult_w4s_it?}'
    print(flag)
