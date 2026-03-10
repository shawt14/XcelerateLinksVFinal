using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace APIPSI16.Migrations
{
    public partial class AddEmployerCandidateHistoryDiscardAndPriority : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsDiscarded",
                table: "EmployerCandidateHistories",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "PriorityId",
                table: "EmployerCandidateHistories",
                type: "int",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsDiscarded",
                table: "EmployerCandidateHistories");

            migrationBuilder.DropColumn(
                name: "PriorityId",
                table: "EmployerCandidateHistories");
        }
    }
}
