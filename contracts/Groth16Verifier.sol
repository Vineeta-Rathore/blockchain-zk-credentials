// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 5744366130708794224752519990566650360180852401536326311676179287677139752925;
    uint256 constant alphay  = 12158822982030987556734607178228714330164036434080281820454872834270548772634;
    uint256 constant betax1  = 6430938204638275004669276460643733658471873788207044897203123808951277339770;
    uint256 constant betax2  = 16546468521734453592666434681481170893221009281426149562651085414642792948349;
    uint256 constant betay1  = 13324474937661619423600477023071216423420918177440510041161646138378717224192;
    uint256 constant betay2  = 8696381829470339863091688002552803374219672338460644792969986017886910929018;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant deltax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant deltay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant deltay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;

    
    uint256 constant IC0x = 1467140450941177127331497889420459217379987396770721852425526109074149804746;
    uint256 constant IC0y = 16642630004218448423697244356446739778617499509227471641059394828684255872737;
    
    uint256 constant IC1x = 13584755532116155947056449020811358916249527871043808910323248424207291689492;
    uint256 constant IC1y = 2225321720685989245732372411201768506630960401032485435816347043398883514238;
    
    uint256 constant IC2x = 2592573434186821351482698279011642100898366420647944898003239604254440536526;
    uint256 constant IC2y = 2388353194670203375435049599188318975291801012570889137211206566437485046336;
    
    uint256 constant IC3x = 7234496633487565481398313150155959261113048438199378566692531774229270098967;
    uint256 constant IC3y = 6213582692568993138942111494262291157853575106787712051649861262035578121552;
    
    uint256 constant IC4x = 2453252448629353558517781998164721690956948963694503971998861533216978185952;
    uint256 constant IC4y = 4115698727984698610007014262008814063225527571318256841154772522717596344789;
    
    uint256 constant IC5x = 1514498148802137912076404025080703303964913357991406982029647862715954953638;
    uint256 constant IC5y = 397158338157784897979424457835555597352606782681516223534499064600744757555;
    
    uint256 constant IC6x = 4438659893911457900273106952987313238097598599964835252843706621259396118105;
    uint256 constant IC6y = 20342883048548335143740588416916759433963030862810972893820371986429710175593;
    
    uint256 constant IC7x = 13348284126555250490463893345526076929467270981808127392771513505436857544819;
    uint256 constant IC7y = 1808265832176992772070737559436024215897621307559436340693307473266749241351;
    
    uint256 constant IC8x = 15135349213105704785428884769258444907203933673741251660286570732172903696843;
    uint256 constant IC8y = 16791593493259001870109064230303745524480604273451505501550430920688109860873;
    
    uint256 constant IC9x = 12923588103266013111961323086048451278632239619600589265787140211797288026843;
    uint256 constant IC9y = 4804664412145212478879322879453740958838188769187293791955208918835757344509;
    
    uint256 constant IC10x = 7444256592759789588043284989560363714636659532536227863971808787775236280980;
    uint256 constant IC10y = 6845373773805474239472600814653731621940793811703316799168950445426655024120;
    
    uint256 constant IC11x = 13826259354308011750543771018979913034727173227697674789432245319360669339390;
    uint256 constant IC11y = 14729364691727005374761699020734598117964225829159020470493586119554148171474;
    
    uint256 constant IC12x = 18091333346916679604842555567898275749768980370940992661939939782028100030798;
    uint256 constant IC12y = 13662933659077518391374410401478907896980178045390829785914972384536923460522;
    
    uint256 constant IC13x = 12256460314086788564723839382628840018064982764965295944440733066832917595314;
    uint256 constant IC13y = 19839721527560517553166555459050605092477675381579015347477477041449631976938;
    
    uint256 constant IC14x = 12601100771265499281182798014562034669666689586689731949209025283233447382897;
    uint256 constant IC14y = 14516479511440712388043072391130196646992349538058851977741828610589364408104;
    
    uint256 constant IC15x = 17542375955204418508948634685013413472518269985831514782099919515253786054348;
    uint256 constant IC15y = 11161037802516987555477157351718959126621893269001130106729688049880491196748;
    
    uint256 constant IC16x = 12572079282208210793394267642681567916967401745200885723858993655184655124505;
    uint256 constant IC16y = 467564563665664869595500382166352173647633574047140838512028218351410182818;
    
    uint256 constant IC17x = 11940344001798962957112143380788755189887755838205393932058865882304279837717;
    uint256 constant IC17y = 2587409334337245778414391644158970429698317620482496076395808869756409281840;
    
    uint256 constant IC18x = 6000435308627153660395378324053393479455276653915399759714199567205327575964;
    uint256 constant IC18y = 12995835861243624490789897973315279394700435186371169148894286518585487333629;
    
    uint256 constant IC19x = 13310350483744259245040241113602883629253477684474574811783502682450825294712;
    uint256 constant IC19y = 17400100276049133577615561671760728148959696438483142324418255295599336216146;
    
    uint256 constant IC20x = 1079683325322169404943462847776988570402487424221689849617940118381892660194;
    uint256 constant IC20y = 2158052882121625100405976563402012791334396269724279660404316655110521280187;
    
    uint256 constant IC21x = 15915389180961779118293334086680243137733234215321184619729482808933567380249;
    uint256 constant IC21y = 20102137738426190291823112313416686404721170267787704847693755634329324672009;
    
    uint256 constant IC22x = 21506952160825038643800884256770956385812433303819654533140151310149261451599;
    uint256 constant IC22y = 1340718748963080701289546512664547625750435337378669661516613091954096764186;
    
    uint256 constant IC23x = 12004158461935910746771694754817418041588322635472130678741213466296931630810;
    uint256 constant IC23y = 16007358021846864186063605115996667875154971536373299608688655162591604021074;
    
    uint256 constant IC24x = 12255157055130059358193509943383488770028290434368194066777553757036665499634;
    uint256 constant IC24y = 5018952892985082718247934031143266098725129153824261325167440000418135537839;
    
    uint256 constant IC25x = 19520220269054223577035303012296204622619876547062579960816052973611543059957;
    uint256 constant IC25y = 21411840272199727564454850237835351672450070617152117958916928517392160073488;
    
    uint256 constant IC26x = 925596296659718616544715189619312968038137514156708012144554327950401952194;
    uint256 constant IC26y = 18024793956582904198121997489949677114885482937857266183176507785080394303255;
    
    uint256 constant IC27x = 1902540435929100502463876011396763983988837034903785088110825079482806896074;
    uint256 constant IC27y = 20247722309353651099815008262129590975650855624567935182343167710540896155487;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[27] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
