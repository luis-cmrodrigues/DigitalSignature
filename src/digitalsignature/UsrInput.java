/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package digitalsignature;

import java.util.Scanner;

/**
 *
 * @author Luis Rodrigues
 */
public class UsrInput {
    /** função para leitura de um numero fornecido pelo user
     * 
     * @return int
     */
    public static int readInt() {
        Scanner reader = new Scanner(System.in);  // Reading from System.in
        System.out.println("Enter a number: ");
        int n = reader.nextInt(); // Scans the next token of the input as an int.
        //once finished
        reader.close();

        return n;
    }


}
