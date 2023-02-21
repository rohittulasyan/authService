using System.ComponentModel.DataAnnotations;

namespace AuthService.Application.Models.DTO;

public class UserLoginDTO {

    [Required]
    public string Email { get; set; }

    [Required]
    public string Password { get; set; }


}