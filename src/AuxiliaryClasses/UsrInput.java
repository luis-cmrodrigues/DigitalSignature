/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package AuxiliaryClasses;

import java.util.Scanner;

/**
 *
 * @author Luis Rodrigues
 */
public class UsrInput {
    /** função para leitura de um numero fornecido pelo user
     * 
     * @param sc
     * @return int
     */
    public static int readInt(Scanner sc) {
        //Scanner reader = new Scanner(System.in);  // Reading from System.in
        System.out.println("Enter a number: ");
        int n = sc.nextInt(); // Scans the next token of the input as an int.
        //once finished
        return n;
    }


}
