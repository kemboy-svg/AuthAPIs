namespace AuthAPIs.Model.AuthDTOs
{
    public class ConfirmEmailDTO
    {
        public string UserID { get; set; } = null!;

        public string Token { get; set; } = null!;
    }
}
