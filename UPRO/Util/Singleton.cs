namespace UPRO.Util
{
    //싱글톤 인스턴스
    public class Singleton
    {
        private static Singleton instance;
        public static Singleton Instance => instance ?? (instance = new Singleton());
        public string ClientPath { get; set; }
    }
}
