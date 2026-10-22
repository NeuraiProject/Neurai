// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
// Uses the separately pinned upstream Java implementation, never the C code.
import fr.cryptohash.*;
import java.io.*;
import java.util.*;

public class SphReference {
    static Digest component(int id) {
        switch(id) {
            case 0:return new BLAKE512(); case 1:return new BMW512();
            case 2:return new Groestl512(); case 3:return new JH512();
            case 4:return new Keccak512(); case 5:return new Skein512();
            case 6:return new Luffa512(); case 7:return new CubeHash512();
            case 8:return new SHAvite512(); case 9:return new SIMD512();
            case 10:return new ECHO512(); case 11:return new Hamsi512();
            case 12:return new Fugue512(); case 13:return new Shabal512();
            case 14:return new Whirlpool(); case 15:return new SHA512();
            default:throw new IllegalArgumentException("algorithm");
        }
    }
    static byte[] unhex(String s) {
        if(s.equals("-"))return new byte[0];
        byte[] b=new byte[s.length()/2];
        for(int i=0;i<b.length;i++)b[i]=(byte)Integer.parseInt(s.substring(2*i,2*i+2),16);
        return b;
    }
    static String hex(byte[] b, boolean reverse) {
        StringBuilder s=new StringBuilder();
        for(int i=0;i<b.length;i++)s.append(String.format("%02x",b[reverse ? b.length-1-i : i]&255));
        return s.toString();
    }
    public static void main(String[] args)throws Exception {
        BufferedReader input=new BufferedReader(new InputStreamReader(System.in));
        for(String line;(line=input.readLine())!=null;) {
            String[] parts=line.split(" ");int op=Integer.parseInt(parts[0]);byte[] data=unhex(parts[1]);
            if(op<16){System.out.println(hex(component(op).digest(data),false));continue;}
            if(data.length!=80 || op>17)throw new IllegalArgumentException("header");
            byte[] previous=Arrays.copyOfRange(data,4,36);
            byte[] current=data;
            for(int round=0;round<16;round++) {
                // GetNibble(48+round) selects bytes 7..0, high nibble first.
                int value=previous[7-round/2]&255;
                int id=(round%2==0) ? value>>>4 : value&15;
                if(op==17 && (id==4 || id==6 || id==15)) {
                    byte[] tiger=new Tiger().digest(current);
                    current=Arrays.copyOf(tiger,64); // zero-padding matches uint512 output
                }
                current=component(id).digest(current);
            }
            System.out.println(hex(Arrays.copyOf(current,32),true));
        }
    }
}
