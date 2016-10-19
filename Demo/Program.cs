using FirmaElectronicaSII;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Demo
{
    class Program
    {
        static void Main(string[] args)
        {
            Program.PruebaTimbreDD();
            Console.ReadKey();
        }

        //////////////////////////////////////////////////////////////////////
        //// BY: Marcelo Rojas R.
        //// Dt: 16-05-2013
        //// El ejercicio actual representa un ejemplo del SII
        //// Donde se suministra el valor del nodo TED, es decir 
        //// su contenido y posteriormente se calcula el timbre
        //////////////////////////////////////////////////////////////////////
        public static void PruebaTimbreDD()
        {
            ////
            //// Contenido del nodo TED del ejemplo. 
            //// Este es el formato que debe tener los datos
            //// 
            string DD = string.Empty;
            DD += "<DD><RE>97975000-5</RE><TD>33</TD><F>27</F><FE>2003-09-08</FE>";
            DD += "<RR>8414240-9</RR><RSR>JORGE GONZALEZ LTDA</RSR><MNT>502946</M";
            DD += "NT><IT1>Cajon AFECTO</IT1><CAF version=\"1.0\"><DA><RE>97975000-";
            DD += "5</RE><RS>RUT DE PRUEBA</RS><TD>33</TD><RNG><D>1</D><H>200</H>";
            DD += "</RNG><FA>2003-09-04</FA><RSAPK><M>0a4O6Kbx8Qj3K4iWSP4w7KneZYe";
            DD += "J+g/prihYtIEolKt3cykSxl1zO8vSXu397QhTmsX7SBEudTUx++2zDXBhZw==<";
            DD += "/M><E>Aw==</E></RSAPK><IDK>100</IDK></DA><FRMA algoritmo=\"SHA1";
            DD += "withRSA\">g1AQX0sy8NJugX52k2hTJEZAE9Cuul6pqYBdFxj1N17umW7zG/hAa";
            DD += "vCALKByHzdYAfZ3LhGTXCai5zNxOo4lDQ==</FRMA></CAF><TSTED>2003-09";
            DD += "-08T12:28:31</TSTED></DD>";

            ////
            //// Representa la clave privada rescatada desde el CAF que envía el SII
            //// para la prueba propuesta por ellos.
            ////
            string pk = string.Empty;
            pk += "MIIBOwIBAAJBANGuDuim8fEI9yuIlkj+MOyp3mWHifoP6a4oWLSBKJSrd3MpEsZd";
            pk += "czvL0l7t/e0IU5rF+0gRLnU1Mfvtsw1wYWcCAQMCQQCLyV9FxKFLW09yWw7bVCCd";
            pk += "xpRDr7FRX/EexZB4VhsNxm/vtJfDZyYle0Lfy42LlcsXxPm1w6Q6NnjuW+AeBy67";
            pk += "AiEA7iMi5q5xjswqq+49RP55o//jqdZL/pC9rdnUKxsNRMMCIQDhaHdIctErN2hC";
            pk += "IP9knS3+9zra4R+5jSXOvI+3xVhWjQIhAJ7CF0R0S7SIHHKe04NUURf/7RvkMqm1";
            pk += "08k74sdnXi3XAiEAlkWk2vc2HM+a1sCqQxNz/098ketqe7NuidMKeoOQObMCIQCk";
            pk += "FAMS9IcPcMjk7zI2r/4EEW63PSXyN7MFAX7TYe25mw==";


            //// 
            //// Este es el resultado que el SII indica debe obtenerse despues de crear
            //// el timbre sobre los datos expuestos.
            ////
            const string HTIMBRE = "pqjXHHQLJmyFPMRvxScN7tYHvIsty0pqL2LLYaG43jMmnfiZfllLA0wb32lP+HBJ/tf8nziSeorvjlx410ZImw==";


            //// //////////////////////////////////////////////////////////////////
            //// Generar timbre sobre los datos del tag DD utilizando la clave 
            //// privada suministrada por el SII en el archivo CAF
            //// //////////////////////////////////////////////////////////////////

            ////
            //// Calcule el hash de los datos a firmar DD
            //// transformando la cadena DD a arreglo de bytes, luego con
            //// el objeto 'SHA1CryptoServiceProvider' creamos el Hash del
            //// arreglo de bytes que representa los datos del DD
            ASCIIEncoding ByteConverter = new ASCIIEncoding();
            byte[] bytesStrDD = ByteConverter.GetBytes(DD);
            byte[] HashValue = new SHA1CryptoServiceProvider().ComputeHash(bytesStrDD);

            ////
            //// Cree el objeto Rsa para poder firmar el hashValue creado
            //// en el punto anterior. La clase FuncionesComunes.crearRsaDesdePEM()
            //// Transforma la llave rivada del CAF en formato PEM a el objeto
            //// Rsa necesario para la firma.
            RSACryptoServiceProvider rsa = FuncionesComunes.crearRsaDesdePEM(pk);

            ////
            //// Firme el HashValue ( arreglo de bytes representativo de DD )
            //// utilizando el formato de firma SHA1, lo cual regresará un nuevo 
            //// arreglo de bytes.
            byte[] bytesSing = rsa.SignHash(HashValue, "SHA1");

            ////
            //// Recupere la representación en base 64 de la firma, es decir de
            //// el arreglo de bytes 
            string FRMT1 = Convert.ToBase64String(bytesSing);

            ////
            //// Comprobación del timbre generado por nuestra rutina contra el
            //// valor 
            if (HTIMBRE.Equals(FRMT1))
            {
                Console.WriteLine("Comprobacion OK");
            }
            else
            {
                Console.WriteLine("Comprobacion NOK");
            }
        }
    }
}
