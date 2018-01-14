if (nonce.length != 8)
            throw new RuntimeException("nonce.length != 8");

        int hashWords = params.getHASH_BYTES() / 4;
        int w = params.getMIX_BYTES() / params.getWORD_BYTES();
        int mixhashes = params.getMIX_BYTES() / params.getHASH_BYTES();
        int[] s = bytesToInts(HashUtil.sha512(merge(blockHeaderTruncHash, reverse(nonce))), false);
        int[] mix = new int[params.getMIX_BYTES() / 4];
        int i = 0;
        while(i<mixhashes) {
            arraycopy(s, 0, mix, i * s.length, s.length);
            i++;
        }

        int numFullPages = (int) (fullSize / params.getMIX_BYTES());
        i=0;
        while(i < params.getACCESSES()){
            int p = remainderUnsigned(fnv(i ^ s[0], mix[i % w]), numFullPages);
            int[] newData = new int[mix.length];
            int off = p * mixhashes;
            int j = 0;
            while(j<mixhashes){
                int itemIdx = off + j;
                if (!full) {
                    int[] lookup1 = calcDatasetItem(cacheOrDataset, itemIdx);
                    arraycopy(lookup1, 0, newData, j * lookup1.length, lookup1.length);
                } else {
                    arraycopy(cacheOrDataset, itemIdx * hashWords, newData, j * hashWords, hashWords);
                }
                j++;
            }
            int i1 = 0;
            while(i1<mix.length){
                mix[i1] = fnv(mix[i1], newData[i1]);
                i1++;
            }
            i++;
        }

        int[] cmix = new int[mix.length / 4];
        i=0;
        while(i<mix.length){
            int fnv1 = fnv(mix[i], mix[i + 1]);
            int fnv2 = fnv(fnv1, mix[i + 2]);
            int fnv3 = fnv(fnv2, mix[i + 3]);
            cmix[i >> 2] = fnv3;
            i += 4;
        }

        return Pair.of(intsToBytes(cmix, false), sha3(merge(intsToBytes(s, false), intsToBytes(cmix, false))));