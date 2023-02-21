using System.ComponentModel.DataAnnotations;

namespace AuthService.Application.Models.DTO;

public class CreateClientDTO {

    [Required]
    public string ClientId { get; set; }

    [Required]
    public string ClientSecret { get; set; }


}